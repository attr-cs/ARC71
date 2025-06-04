const { Telegraf } = require('telegraf');
const mongoose = require('mongoose');
const axios = require('axios');
const { GoogleGenAI, createPartFromUri } = require('@google/genai');
const { Buffer } = require('buffer');
const sharp = require('sharp');
require('dotenv').config();

// Initialize bot
const bot = new Telegraf(process.env.BOT_TOKEN);

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  userId: String,
  firstName: String,
  username: String,
  imagesGenerated: { type: Number, default: 0 },
  imagesProcessed: { type: Number, default: 0 },
});
const UserSchema = mongoose.model('User', userSchema);

const configSchema = new mongoose.Schema({
  key: String,
  value: String,
});
const ConfigSchema = mongoose.model('Config', configSchema);

const imageSchema = new mongoose.Schema({
  userId: String,
  username: String,
  prompt: String,
  encodedImage: String,
  timestamp: { type: Date, default: Date.now },
});
const ImageSchema = mongoose.model('Image', imageSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err.message));

// User agents for rotation
const userAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1'
];

// Global variables
let imageToken = process.env.IMAGE_TOKEN;
const geminiApiKeys = [
  process.env.GEMINI_API_KEY_1,
  process.env.GEMINI_API_KEY_2,
  process.env.GEMINI_API_KEY_3,
].filter(key => key);
const keyStatus = geminiApiKeys.map(() => ({ rateLimitedUntil: 0 }));
const rateLimitedUntil = { timestamp: 0 };

// Helper functions
async function isAuthorizedUser(userId) {
  const allowedUsers = await ConfigSchema.findOne({ key: 'allowedUsers' });
  const blockedUsers = await ConfigSchema.findOne({ key: 'blockedUsers' });
  if (blockedUsers && blockedUsers.value.split(',').includes(userId)) {
    return false; // Silently block user
  }
  return userId === process.env.ADMIN_ID || (allowedUsers && allowedUsers.value.split(',').includes(userId));
}

async function isAuthorizedGroup(chatId) {
  const allowedGroups = await ConfigSchema.findOne({ key: 'allowedGroups' });
  return allowedGroups && allowedGroups.value.split(',').includes(chatId.toString());
}

async function isDmAllowed() {
  const dmConfig = await ConfigSchema.findOne({ key: 'dmAllowed' });
  return dmConfig && dmConfig.value === 'true';
}

async function getAspectRatio() {
  const config = await ConfigSchema.findOne({ key: 'aspectRatio' });
  const ratio = config ? config.value.toLowerCase() : 'landscape';
  return {
    landscape: 'IMAGE_ASPECT_RATIO_LANDSCAPE',
    portrait: 'IMAGE_ASPECT_RATIO_PORTRAIT',
    square: 'IMAGE_ASPECT_RATIO_SQUARE'
  }[ratio] || 'IMAGE_ASPECT_RATIO_LANDSCAPE';
}

async function forwardToAdmin(ctx) {
  if (ctx.from.id.toString() !== process.env.ADMIN_ID && ctx.message) {
    try {
      const userInfo = `User Info:\nID: ${ctx.from.id}\nUsername: @${ctx.from.username || 'N/A'}\nFirst Name: ${ctx.from.first_name || 'N/A'}`;
      const messageContent = ctx.message.text 
        ? `Message: ${ctx.message.text}`
        : ctx.message.caption 
        ? `Caption: ${ctx.message.caption}`
        : 'Non-text message';
      const combinedMessage = `${userInfo}\n${messageContent}`;
      
      await bot.telegram.sendMessage(process.env.ADMIN_ID, combinedMessage);
      
      // Forward non-text messages (e.g., photos, stickers)
      if (!ctx.message.text) {
        await bot.telegram.forwardMessage(
          process.env.ADMIN_ID,
          ctx.chat.id,
          ctx.message.message_id
        );
      }
    } catch (err) {
      console.error('Forwarding error:', err.message);
    }
  }
}

async function sendDebugToAdmin(ctx, message) {
  if (ctx.from.id.toString() !== process.env.ADMIN_ID) {
    try {
      // Truncate message if too long to avoid Telegram limits
      const maxLength = 4096;
      const truncatedMessage = message.length > maxLength ? `${message.slice(0, maxLength - 3)}...` : message;
      await bot.telegram.sendMessage(process.env.ADMIN_ID, truncatedMessage);
    } catch (err) {
      console.error('Debug send error:', err.message);
    }
  }
}

async function updateUserStats(userId, firstName, username, imageCount = 0, processedCount = 0) {
  await UserSchema.findOneAndUpdate(
    { userId },
    { 
      firstName, 
      username, 
      $inc: { 
        imagesGenerated: imageCount, 
        imagesProcessed: processedCount 
      } 
    },
    { upsert: true }
  );
}

async function saveImagesToDb(userId, username, prompt, images) {
  const imageDocs = images.map(img => ({
    userId,
    username,
    prompt,
    encodedImage: img.encodedImage || img.imageBytes || img,
  }));
  await ImageSchema.insertMany(imageDocs);
}

async function showWaitMessage(ctx) {
  const waitMessage = await ctx.reply('wait...', { disable_web_page_preview: true, disable_notification: true });
  return { waitMessage, interval: null }; // No interval for static message
}

async function getRandomUserAgent() {
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

function isValidBase64(str) {
  try {
    return Buffer.from(str, 'base64').toString('base64') === str;
  } catch {
    return false;
  }
}

function getRandomKeyIndex() {
  const now = Date.now();
  const availableKeys = geminiApiKeys
    .map((key, index) => ({ key, index }))
    .filter((_, i) => keyStatus[i].rateLimitedUntil < now);
  if (availableKeys.length === 0) return Math.floor(Math.random() * geminiApiKeys.length);
  return availableKeys[Math.floor(Math.random() * availableKeys.length)].index;
}

async function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// Middleware for restricted commands
async function checkAuth(ctx, next) {
  const userId = ctx.from.id.toString();
  const chatId = ctx.chat.id.toString();

  // Check if user is authorized first (includes blocked users check)
  if (!(await isAuthorizedUser(userId))) {
    await forwardToAdmin(ctx); // Still forward for admin visibility
    return; // Silently ignore blocked or unauthorized users
  }

  await forwardToAdmin(ctx);

  if (ctx.chat.type !== 'private' && !(await isAuthorizedGroup(chatId))) {
    await ctx.reply('Group not authorized.');
    return;
  }

  if (ctx.chat.type === 'private' && !(await isDmAllowed()) && userId !== process.env.ADMIN_ID) {
    await ctx.reply('DM usage is disabled.');
    return;
  }

  await next();
}

// Admin-only middleware
async function checkAdmin(ctx, next) {
  if (ctx.from.id.toString() !== process.env.ADMIN_ID) {
    await ctx.reply('Only admins can use this command.');
    return;
  }
  await next();
}

// Forward all messages to admin
bot.use(async (ctx, next) => {
  if (ctx.message) {
    await forwardToAdmin(ctx);
  }
  await next();
});

// Commands
bot.command('start', async (ctx) => {
  await ctx.reply('Ready');
});

bot.command('id', async (ctx) => {
  const chat = ctx.chat;
  const user = ctx.from;
  const groupInfo = chat.type !== 'private' ? {
    groupId: chat.id,
    groupTitle: chat.title || 'N/A',
    groupType: chat.type,
  } : {};
  await ctx.reply(`User ID: ${user.id}\nUsername: @${user.username || 'N/A'}\nFirst Name: ${user.first_name || 'N/A'}\n${chat.type !== 'private' ? `Group ID: ${groupInfo.groupId}\nGroup Title: ${groupInfo.groupTitle}` : ''}`);
});

bot.command('id', checkAdmin, async (ctx) => {
  const args = ctx.message.text.split(' ');
  if (args.length > 1) {
    const groupId = args[1];
    try {
      const currentGroups = await ConfigSchema.findOne({ key: 'allowedGroups' });
      const groups = currentGroups ? currentGroups.value.split(',').filter(id => id) : [];
      if (!groups.includes(groupId)) {
        groups.push(groupId);
        await ConfigSchema.findOneAndUpdate(
          { key: 'allowedGroups' },
          { value: groups.join(',') },
          { upsert: true }
        );
        await ctx.reply(`Group ${groupId} authorized.`);
      } else {
        await ctx.reply(`Group ${groupId} is already authorized.`);
      }
    } catch (err) {
      console.error('Error authorizing group:', err.message);
      await ctx.reply('Error authorizing group.');
    }
  }
});

bot.command('allow', checkAdmin, async (ctx) => {
  const args = ctx.message.text.split(' ');
  if (args.length > 1) {
    const id = args[1];
    try {
      if (id.startsWith('-')) {
        // Group ID
        const currentGroups = await ConfigSchema.findOne({ key: 'allowedGroups' });
        const groups = currentGroups ? currentGroups.value.split(',').filter(g => g) : [];
        if (!groups.includes(id)) {
          groups.push(id);
          await ConfigSchema.findOneAndUpdate(
            { key: 'allowedGroups' },
            { value: groups.join(',') },
            { upsert: true }
          );
          await ctx.reply(`Group ${id} authorized.`);
        } else {
          await ctx.reply(`Group ${id} is already authorized.`);
        }
      } else {
        // User ID
        const currentUsers = await ConfigSchema.findOne({ key: 'allowedUsers' });
        const users = currentUsers ? currentUsers.value.split(',').filter(u => u) : [];
        if (!users.includes(id)) {
          users.push(id);
          await ConfigSchema.findOneAndUpdate(
            { key: 'allowedUsers' },
            { value: users.join(',') },
            { upsert: true }
          );
          await ctx.reply(`User ${id} authorized.`);
        } else {
          await ctx.reply(`User ${id} is already authorized.`);
        }
      }
    } catch (err) {
      console.error('Error authorizing:', err.message);
      await ctx.reply('Error authorizing ID.');
    }
  } else if (ctx.message.reply_to_message) {
    const userId = ctx.message.reply_to_message.from.id.toString();
    try {
      const allowedUsers = await ConfigSchema.findOne({ key: 'allowedUsers' });
      const users = allowedUsers ? allowedUsers.value.split(',').filter(u => u) : [];
      if (!users.includes(userId)) {
        users.push(userId);
        await ConfigSchema.findOneAndUpdate(
          { key: 'allowedUsers' },
          { value: users.join(',') },
          { upsert: true }
        );
        await ctx.reply(`User ${userId} authorized.`);
      } else {
        await ctx.reply('User already authorized.');
      }
    } catch (err) {
      console.error('Error authorizing user:', err.message);
      await ctx.reply('Error authorizing user.');
    }
  } else {
    await ctx.reply('Provide an ID (/allow <id>) or reply to a user’s message.');
  }
});

bot.command('block', checkAdmin, async (ctx) => {
  const args = ctx.message.text.split(' ');
  if (args.length > 1) {
    const userId = args[1];
    try {
      const blockedUsers = await ConfigSchema.findOne({ key: 'blockedUsers' });
      const users = blockedUsers ? blockedUsers.value.split(',').filter(u => u) : [];
      if (!users.includes(userId)) {
        users.push(userId);
        await ConfigSchema.findOneAndUpdate(
          { key: 'blockedUsers' },
          { value: users.join(',') },
          { upsert: true }
        );
        await ctx.reply(`User ${userId} blocked silently.`);
      } else {
        await ctx.reply(`User ${userId} is already blocked.`);
      }
    } catch (err) {
      console.error('Error blocking user:', err.message);
      await ctx.reply('Error blocking user.');
    }
  } else if (ctx.message.reply_to_message) {
    const userId = ctx.message.reply_to_message.from.id.toString();
    try {
      const blockedUsers = await ConfigSchema.findOne({ key: 'blockedUsers' });
      const users = blockedUsers ? blockedUsers.value.split(',').filter(u => u) : [];
      if (!users.includes(userId)) {
        users.push(userId);
        await ConfigSchema.findOneAndUpdate(
          { key: 'blockedUsers' },
          { value: users.join(',') },
          { upsert: true }
        );
        await ctx.reply(`User ${userId} blocked silently.`);
      } else {
        await ctx.reply(`User ${userId} is already blocked.`);
      }
    } catch (err) {
      console.error('Error blocking user:', err.message);
      await ctx.reply('Error blocking user.');
    }
  } else {
    await ctx.reply('Provide a user ID (/block <id>) or reply to a user’s message.');
  }
});

bot.command('enable_dm', checkAdmin, async (ctx) => {
  await ConfigSchema.findOneAndUpdate(
    { key: 'dmAllowed' },
    { value: 'true' },
    { upsert: true }
  );
  await ctx.reply('DM usage enabled for all.');
});

bot.command('disable_dm', checkAdmin, async (ctx) => {
  await ConfigSchema.findOneAndUpdate(
    { key: 'dmAllowed' },
    { value: 'false' },
    { upsert: true }
  );
  await ctx.reply('DM usage disabled for all.');
});

bot.command('set_token', checkAdmin, async (ctx) => {
  const token = ctx.message.text.split(' ')[1];
  if (!token) {
    await ctx.reply('Please provide a token.');
    return;
  }
  imageToken = token;
  await ctx.reply('Image token updated.');
});

bot.command('aspect', async (ctx) => {
  const args = ctx.message.text.split(' ');
  if (args.length > 1 && ctx.from.id.toString() === process.env.ADMIN_ID) {
    const ratio = args[1].toLowerCase();
    if (['landscape', 'portrait', 'square'].includes(ratio)) {
      await ConfigSchema.findOneAndUpdate(
        { key: 'aspectRatio' },
        { value: ratio },
        { upsert: true }
      );
      await ctx.reply(`Aspect ratio set to ${ratio}.`);
    } else {
      await ctx.reply('Invalid ratio. Use: landscape, portrait, or square.');
    }
  } else {
    const currentRatio = await ConfigSchema.findOne({ key: 'aspectRatio' });
    await ctx.reply(`Current aspect ratio: ${currentRatio ? currentRatio.value : 'landscape'}`);
  }
});

bot.command('ping', async (ctx) => {
  const start = process.hrtime.bigint();
  await ctx.reply('Pinging...');
  const end = process.hrtime.bigint();
  const latency = Number(end - start) / 1_000_000;
  await ctx.reply(`Latency: ${latency.toFixed(2)}ms`);
});

bot.command('stats', checkAuth, async (ctx) => {
  const userCount = await UserSchema.countDocuments();
  const totalImages = await UserSchema.aggregate([{ $group: { _id: null, total: { $sum: '$imagesGenerated' } } }]);
  const totalProcessed = await UserSchema.aggregate([{ $group: { _id: null, total: { $sum: '$imagesProcessed' } } }]);
  const allowedGroups = await ConfigSchema.findOne({ key: 'allowedGroups' });
  const groupCount = allowedGroups ? allowedGroups.value.split(',').filter(id => id).length : 0;
  await ctx.reply(`Users: ${userCount}\nAuthorized Groups: ${groupCount}\nImages Generated: ${totalImages[0]?.total || 0}\nImages Processed: ${totalProcessed[0]?.total || 0}`);
});

bot.command('cmds', async (ctx) => {
  const isAdmin = ctx.from.id.toString() === process.env.ADMIN_ID;
  const isAuth = await isAuthorizedUser(ctx.from.id.toString()) && (ctx.chat.type === 'private' ? await isDmAllowed() || isAdmin : await isAuthorizedGroup(ctx.chat.id.toString()));
  const commands = [
    '/start - Start bot',
    '/id - Show user/chat IDs',
    '/ping - Check latency',
    '/aspect - Show aspect ratio',
    ...(isAuth ? [
      '/stats - Show bot stats',
      '/i - Generate 4 images (Imagen3)',
      '/g - Generate 1 image (Imagen4)',
      '/edit - Edit image with prompt',
      '/ic - Describe/ask about image',
      '/sti - Convert sticker to image/GIF',
      '/its - Convert image to sticker'
    ] : []),
    ...(isAdmin ? [
      '/allow - Authorize user or group',
      '/block - Silently block user',
      '/enable_dm - Allow DMs',
      '/disable_dm - Block DMs',
      '/set_token - Update image token',
      '/aspect <ratio> - Set aspect ratio (landscape, portrait, square)'
    ] : [])
  ];
  await ctx.reply(`Commands:\n${commands.join('\n')}`);
});

bot.command(['i', 'I'], checkAuth, async (ctx) => {
  const prompt = ctx.message.text.split(' ').slice(1).join(' ');
  if (!prompt) {
    await ctx.reply('Please provide a prompt for Imagen3.');
    return;
  }

  const { waitMessage } = await showWaitMessage(ctx);
  try {
    const aspectRatio = await getAspectRatio();
    const data = JSON.stringify({
      userInput: { candidatesCount: 4, prompts: [prompt], seed: 206167 },
      clientContext: { sessionId: `;${Date.now()}`, tool: "IMAGE_FX" },
      modelInput: { modelNameType: "IMAGEN_3_1" },
      aspectRatio
    });

    const config = {
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://aisandbox-pa.googleapis.com/v1:runImageFx',
      headers: {
        'accept': '*/*',
        'authorization': `Bearer ${imageToken}`,
        'content-type': 'text/plain;charset=UTF-8',
        'origin': 'https://labs.google',
        'user-agent': await getRandomUserAgent()
      },
      data: data
    };

    const response = await axios.request(config);

    await sendDebugToAdmin(ctx, `Imagen3 Response: Success (status ${response.status})`);

    if (!response.data?.imagePanels?.[0]?.generatedImages || !Array.isArray(response.data.imagePanels[0].generatedImages)) {
      await sendDebugToAdmin(ctx, `Imagen3 Error: Invalid response structure`);
      throw new Error('No images generated. Response structure invalid.');
    }

    const images = response.data.imagePanels[0].generatedImages;
    if (images.length === 0) {
      await sendDebugToAdmin(ctx, `Imagen3 Error: Empty images array`);
      throw new Error('No images generated.');
    }

    const mediaGroup = images
      .filter(img => img.encodedImage && isValidBase64(img.encodedImage))
      .map(img => ({
        type: 'photo',
        media: { source: Buffer.from(img.encodedImage, 'base64') }
      }));

    if (mediaGroup.length === 0) {
      await sendDebugToAdmin(ctx, `Imagen3 Error: No valid images`);
      throw new Error('No valid images generated.');
    }

    await ctx.replyWithMediaGroup(mediaGroup);
    await updateUserStats(ctx.from.id.toString(), ctx.from.first_name, ctx.from.username, mediaGroup.length);
    await saveImagesToDb(ctx.from.id.toString(), ctx.from.username, prompt, images);
  } catch (error) {
    const errorMessage = error.response?.status === 401
      ? 'Authentication failed. Please update token with /set_token.'
      : error.response?.status === 429
      ? `Rate limit exceeded. Please try again in ${error.response?.data?.parameters?.retry_after || 30} seconds.`
      : error.response?.status === 503
      ? 'Imagen3 service is temporarily overloaded. Please try again later.'
      : `Error: ${error.message}`;
    await ctx.reply(errorMessage);
    await sendDebugToAdmin(ctx, `Imagen3 Error: ${error.message} (status ${error.response?.status || 'N/A'})`);
  } finally {
    await bot.telegram.deleteMessage(ctx.chat.id, waitMessage.message_id).catch(() => {});
  }
});

bot.command('g', checkAuth, async (ctx) => {
  const prompt = ctx.message.text.split(' ').slice(1).join(' ');
  if (!prompt) {
    await ctx.reply('Please provide a prompt for Imagen4.');
    return;
  }

  const { waitMessage } = await showWaitMessage(ctx);
  try {
    if (!imageToken) {
      throw new Error('Image token not set. Please set it with /set_token.');
    }

    const now = Date.now();
    if (rateLimitedUntil.timestamp > now) {
      await ctx.reply(`Rate limit active until ${new Date(rateLimitedUntil.timestamp).toISOString()}. Please try again later.`);
      return;
    }

    const seed = Math.floor(Math.random() * 1000000);
    const aspectRatio = await getAspectRatio();
    const config = {
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://aisandbox-pa.googleapis.com/v1/whisk:generateImage',
      headers: {
        'accept': '*/*',
        'authorization': `Bearer ${imageToken}`,
        'content-type': 'text/plain;charset=UTF-8',
        'origin': 'https://labs.google',
        'user-agent': getRandomUserAgent()
      },
      data: JSON.stringify({
        clientContext: {
          workflowId: "91cbbef0-75a4-4352-8d03-4f66226c6afc",
          tool: "BACKBONE",
          sessionId: `;${Date.now()}`
        },
        imageModelSettings: {
          imageModel: "IMAGEN_3_5",
          aspectRatio
        },
        seed: seed,
        prompt: prompt,
        mediaCategory: "MEDIA_CATEGORY_BOARD"
      })
    };

    const response = await axios.request(config);

    await sendDebugToAdmin(ctx, `Imagen4 Response: Success (status ${response.status})`);

    if (!response.data?.imagePanels?.[0]?.generatedImages?.[0]?.encodedImage) {
      await sendDebugToAdmin(ctx, `Imagen4 Error: Invalid response structure`);
      throw new Error('Invalid response structure.');
    }

    const image = response.data.imagePanels[0].generatedImages[0];
    if (!image.encodedImage || !isValidBase64(image.encodedImage)) {
      await sendDebugToAdmin(ctx, `Imagen4 Error: Invalid image data`);
      throw new Error('Invalid image data.');
    }

    await ctx.replyWithPhoto({ source: Buffer.from(image.encodedImage, 'base64') });
    await updateUserStats(ctx.from.id.toString(), ctx.from.first_name, ctx.from.username, 1);
    await saveImagesToDb(ctx.from.id.toString(), ctx.from.username, prompt, [image]);
  } catch (error) {
    const errorMessage = error.response?.status === 401
      ? 'Authentication failed. Please update token with /set_token.'
      : error.response?.status === 429
      ? `Rate limit exceeded. Please try again in ${error.response?.data?.parameters?.retry_after || 30} seconds.`
      : error.response?.status === 503
      ? 'Imagen4 service is temporarily overloaded.'
      : `Error: ${error.message}`;
    await ctx.reply(errorMessage);
    await sendDebugToAdmin(ctx, `Imagen4 Error: ${error.message} (status ${error.response?.status || 'N/A'})`);
  } finally {
    await bot.telegram.deleteMessage(ctx.chat.id, waitMessage.message_id).catch(() => {});
  }
});

bot.command('edit', checkAuth, async (ctx) => {
  if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.photo) {
    await ctx.reply('Reply to an image with a prompt to edit.');
    return;
  }

  const prompt = ctx.message.text.split(' ').slice(1).join(' ');
  if (!prompt) {
    await ctx.reply('Please provide an edit prompt.');
    return;
  }

  const { waitMessage } = await showWaitMessage(ctx);
  try {
    const photo = ctx.message.reply_to_message.photo.pop();
    const file = await bot.telegram.getFileLink(photo.file_id);
    const response = await axios.get(file, { responseType: 'arraybuffer' });

    let success = false;
    let lastError = null;
    const triedKeys = new Set();

    for (let i = 0; i < geminiApiKeys.length; i++) {
      const keyIndex = getRandomKeyIndex();
      if (triedKeys.has(keyIndex)) continue;
      triedKeys.add(keyIndex);
      const apiKey = geminiApiKeys[keyIndex];
      try {
        const ai = new GoogleGenAI({ apiKey });
        const contents = [
          { text: prompt },
          { inlineData: { mimeType: 'image/png', data: Buffer.from(response.data).toString('base64') } }
        ];

        const geminiResponse = await ai.models.generateContent({
          model: 'gemini-2.0-flash-preview-image-generation',
          contents,
          config: {
            responseModalities: ['TEXT', 'IMAGE']
          }
        });

        await sendDebugToAdmin(ctx, `Gemini Edit Response: Success (key index ${keyIndex})`);
        for (const part of geminiResponse.candidates[0].content.parts) {
          if (part.inlineData && isValidBase64(part.inlineData.data)) {
            const buffer = Buffer.from(part.inlineData.data, 'base64');
            await ctx.replyWithPhoto({ source: buffer });
            await updateUserStats(ctx.from.id.toString(), ctx.from.first_name, ctx.from.username, 1);
            success = true;
            break;
          }
        }
        if (success) break;
      } catch (error) {
        lastError = error;
        await sendDebugToAdmin(ctx, `Gemini Edit Error (key ${keyIndex}): ${error.message} (status ${error.response?.status || 'N/A'})`);
        if (error.response?.status === 429) {
          keyStatus[keyIndex].rateLimitedUntil = Date.now() + 60_000;
        } else if (error.response?.status === 503) {
          await delay(2000);
          continue;
        }
      }
    }

    if (!success) {
      await sendDebugToAdmin(ctx, `Gemini Edit Error: No image generated`);
      throw new Error('No image generated.');
    }
  } catch (error) {
    const errorMessage = error.response?.status === 401
      ? 'Gemini authentication failed. Contact admin to update API keys.'
      : error.response?.status === 429
      ? 'Gemini rate limit exceeded. Try again later.'
      : error.response?.status === 503
      ? 'Gemini model is temporarily overloaded. Please try again in a few minutes.'
      : error.response?.status === 400
      ? 'Invalid request to Gemini. Check prompt or image format.'
      : error.message.includes('model does not support')
      ? 'Image editing not supported in this region or model.'
      : `Error: ${error.message}`;
    await ctx.reply(errorMessage);
    await sendDebugToAdmin(ctx, `Gemini Edit Error: ${error.message} (status ${error.response?.status || 'N/A'})`);
  } finally {
    await bot.telegram.deleteMessage(ctx.chat.id, waitMessage.message_id).catch(() => {});
  }
});

bot.command('ic', checkAuth, async (ctx) => {
  if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.photo) {
    await ctx.reply('Reply to an image with a prompt to describe or ask about it.');
    return;
  }

  const prompt = ctx.message.text.split(' ').slice(1).join(' ');
  if (!prompt) {
    await ctx.reply('Please provide a prompt (e.g., "What is in this image?").');
    return;
  }

  const { waitMessage } = await showWaitMessage(ctx);
  try {
    const photo = ctx.message.reply_to_message.photo.pop();
    const file = await bot.telegram.getFileLink(photo.file_id);
    const response = await axios.get(file, { responseType: 'arraybuffer' });

    const imageSizeMB = response.data.length / (1024 * 1024);
    let useFilesAPI = imageSizeMB > 20;
    let base64Image = !useFilesAPI ? Buffer.from(response.data).toString('base64') : null;
    let uploadedFile = null;

    let success = false;
    let lastError;
    const triedKeys = new Set();

    for (let i = 0; i < geminiApiKeys.length; i++) {
      const keyIndex = await getRandomKeyIndex();
      if (triedKeys.has(keyIndex)) continue;
      triedKeys.add(keyIndex);
      const apiKey = geminiApiKeys[keyIndex];
      
      for (let attempt = 0; attempt <= 3; attempt++) {
        try {
          const ai = new GoogleGenAI({ apiKey: apiKey });
          
          if (useFilesAPI && !uploadedFile) {
            const tempFilePath = `/tmp/image_${Date.now()}.jpg`;
            require('fs').writeFileSync(tempFilePath, response.data);
            uploadedFile = await ai.files.upload({
              file: tempFilePath,
              config: { mimeType: 'image/jpeg' }
            });
            require('fs').unlinkSync(tempFilePath);
            await sendDebugToAdmin(ctx, `Image uploaded to Files API`);
          }

          const contents = useFilesAPI
            ? [
                createPartFromUri(uploadedFile.uri, uploadedFile.mimeType),
                { text: prompt }
              ]
            : [
                { inlineData: { mimeType: 'image/jpeg', data: base64Image } },
                { text: prompt }
              ];

          const geminiResponse = await ai.models.generateContent({
            model: 'gemini-2.0-flash',
            contents
          });

          await sendDebugToAdmin(ctx, `Gemini API Response: Success (key index ${keyIndex})`);
          const textResponse = geminiResponse.candidates?.[0]?.content?.parts?.[0]?.text;
          if (textResponse) {
            await ctx.reply(textResponse);
            await updateUserStats(ctx.from.id.toString(), ctx.from.first_name, ctx.from.username, 0, 1);
            success = true;
            break;
          } else {
            throw new Error('No text response generated.');
          }
        } catch (error) {
          lastError = error;
          await sendDebugToAdmin(ctx, `Gemini Error (key ${keyIndex}, attempt ${attempt + 1}): ${error.message} (status ${error.response?.status || 'N/A'})`);
          
          if (error.response?.status === 429) {
            keyStatus[keyIndex].rateLimitedUntil = Date.now() + 60_000;
            break;
          } else if (error.response?.status === 503) {
            await delay(2000);
            continue;
          }
          break;
        }
      }
      if (success) break;
    }

    if (!success) {
      await sendDebugToAdmin(ctx, `Gemini Error: No text response after all attempts`);
      throw new Error('No valid text response generated.');
    }
  } catch (error) {
    const errorMessage = error.response?.status === 401
      ? 'Gemini authentication failed. Contact admin to update API keys.'
      : error.response?.status === 429
      ? 'Gemini rate limit exceeded. Please try again later.'
      : error.response?.status === 503
      ? 'Gemini model is temporarily overloaded. Please try again in a few minutes.'
      : error.message.includes('Image exceeds 20MB')
      ? 'Image exceeds 20MB. Please use a smaller image.'
      : `Error: ${error.message}`;
    await ctx.reply(errorMessage);
    await sendDebugToAdmin(ctx, `Gemini Error: ${error.message} (status ${error.response?.status || 'N/A'})`);
  } finally {
    await bot.telegram.deleteMessage(ctx.chat.id, waitMessage.message_id).catch(() => {});
  }
});

bot.command('sti', checkAuth, async (ctx) => {
  if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.sticker) {
    await ctx.reply('Please reply to a sticker with /sti to convert it to an image or GIF.');
    return;
  }

  const { waitMessage } = await showWaitMessage(ctx);
  try {
    const sticker = ctx.message.reply_to_message.sticker;
    const isAnimated = sticker.is_animated;
    const isVideo = sticker.is_video;

    const fileId = sticker.file_id;
    const fileLink = await bot.telegram.getFileLink(fileId);
    const response = await axios.get(fileLink, { responseType: 'arraybuffer' });

    const fileBuffer = Buffer.from(response.data);

    if (isAnimated || isVideo) {
      await ctx.replyWithAnimation({ source: fileBuffer });
    } else {
      await ctx.replyWithDocument({ 
        source: fileBuffer,
        filename: 'sticker.png',
        contentType: 'image/png'
      });
    }

    await updateUserStats(ctx.from.id.toString(), ctx.from.first_name, ctx.from.username || '', 0, 1);
    await saveImagesToDb(ctx.from.id.toString(), ctx.from.username, 'Sticker conversion', [{ encodedImage: Buffer.from(response.data).toString('base64') }]);

  } catch (error) {
    const errorMessage = `Error converting sticker: ${error.message}`;
    await ctx.reply(errorMessage);
    await sendDebugToAdmin(ctx, `Sticker Conversion Error: ${error.message}`);
  } finally {
    await bot.telegram.deleteMessage(ctx.chat.id, waitMessage.message_id).catch(() => {});
  }
});

bot.command('its', checkAuth, async (ctx) => {
  if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.photo) {
    await ctx.reply('Please reply to a photo with /its to convert it to a sticker.');
    return;
  }

  const { waitMessage } = await showWaitMessage(ctx);
  try {
    const photo = ctx.message.reply_to_message.photo.pop();
    const file = await bot.telegram.getFileLink(photo.file_id);
    const response = await axios.get(file, { responseType: 'arraybuffer' });

    const imageSizeMB = response.data.length / (1024 * 1024);
    if (imageSizeMB > 10) {
      throw new Error('Image exceeds 10MB. Please use a smaller image.');
    }

    // Resize image to fit Telegram sticker requirements (512px max dimension)
    const resizedImage = await sharp(response.data)
      .resize({
        width: 512,
        height: 512,
        fit: 'contain',
        background: { r: 0, g: 0, b: 0, alpha: 0 }
      })
      .png()
      .toBuffer();

    // Send as sticker
    await ctx.replyWithSticker({ source: resizedImage });

    await updateUserStats(ctx.from.id.toString(), ctx.from.first_name, ctx.from.username || '', 1, 0);
    await saveImagesToDb(ctx.from.id.toString(), ctx.from.username, 'Image to sticker conversion', [{ encodedImage: resizedImage.toString('base64') }]);
  } catch (error) {
    const errorMessage = error.message.includes('Image exceeds')
      ? error.message
      : `Error converting image to sticker: ${error.message}`;
    await ctx.reply(errorMessage);
    await sendDebugToAdmin(ctx, `Image to Sticker Error: ${error.message}`);
  } finally {
    await bot.telegram.deleteMessage(ctx.chat.id, waitMessage.message_id).catch(() => {});
  }
});

// Start bot
bot.launch();
console.log('Bot started as ARC71');