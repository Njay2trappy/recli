// Import required modules
const { Telegraf } = require('telegraf');
const TonWeb = require('tonweb');
const axios = require('axios');

// Initialize the bot
const bot = new Telegraf('7679256143:AAHNnB6vieOmKnD1lm2oRMS7UNafThA2FAs');

// TON testnet configuration
const tonweb = new TonWeb(new TonWeb.HttpProvider('https://testnet.toncenter.com/api/v2/jsonRPC', {
  apiKey: '8723f42a9a980ba38692832aad3d42fcbe0f0435600c6cd03d403e800bdd2e88'
}));

// Helper function to convert USDT to TON using CoinGecko API
async function convertToTon(amount) {
  console.log(`Converting ${amount} USDT to TON...`);
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=the-open-network&vs_currencies=usd');
    const tonPriceInUsdt = response.data['the-open-network'].usd;
    console.log(`Conversion rate fetched: 1 TON = ${tonPriceInUsdt} USDT`);
    return amount / tonPriceInUsdt;
  } catch (error) {
    console.error('Error fetching conversion rate from CoinGecko API:', error);
    return null;
  }
}

// Start bot command
bot.start((ctx) => {
  console.log('Bot started by user:', ctx.from.id);
  ctx.reply('Welcome! You can make payments on the TON testnet. Enter the recipient wallet address:');
});

let recipientWalletAddress = null;

bot.on('text', async (ctx) => {
  const message = ctx.message.text;
  if (!recipientWalletAddress) {
    recipientWalletAddress = message;
    console.log('Recipient wallet address set:', recipientWalletAddress);
    ctx.reply(`Recipient wallet address saved: ${recipientWalletAddress}. Now enter the amount in USDT:`);
    return;
  }

  console.log('User input received:', message);
  const amount = parseFloat(message);
  if (isNaN(amount)) {
    console.log('Invalid amount entered.');
    ctx.reply('Please enter a valid number.');
    return;
  }

  const tonAmount = await convertToTon(amount);
  if (!tonAmount) {
    console.log('Conversion to TON failed.');
    ctx.reply('Error converting amount. Try again later.');
    return;
  }

  // Generate a new TON wallet address and private key
  console.log('Generating new TON wallet address and private key...');
  const keyPair = TonWeb.utils.newKeyPair();
  const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, { publicKey: keyPair.publicKey, wc: 0 });
  const walletAddress = (await wallet.getAddress()).toString(true, true, false); // Generate in UQ format
  console.log(`Generated wallet address (UQ format): ${walletAddress}`);
  console.log(`Generated private key: ${TonWeb.utils.bytesToHex(keyPair.secretKey)}`);

  ctx.reply(`Send ${tonAmount.toFixed(6)} TON to the following address: ${walletAddress}`);

  // Monitor the address for payment
  console.log('Starting to monitor wallet for payment...');
  const intervalId = setInterval(async () => {
    try {
      const balance = await tonweb.provider.getBalance(walletAddress);
      console.log(`Current balance for ${walletAddress}: ${balance}`);
      if (balance >= tonAmount) {
        clearInterval(intervalId);
        console.log('Payment received. Sending to recipient wallet...');

        // Deduct a fee (e.g., 0.01 TON for transaction cost) before transferring
        const fee = 10000000; // 0.01 TON in nanotons
        const amountToSend = balance - fee;

        if (amountToSend <= 0) {
          console.log('Insufficient funds after deducting transaction fee.');
          ctx.reply('Insufficient funds after deducting transaction fee.');
          return;
        }

        // Send funds to recipient wallet using the private key
        try {
          const generatedWallet = new tonweb.wallet.all.v3R2(tonweb.provider, {
            publicKey: keyPair.publicKey,
            wc: 0,
          });

          const seqno = 0; // Set seqno to 0 for the first transaction

          const transfer = await generatedWallet.methods.transfer({
            secretKey: keyPair.secretKey,
            toAddress: recipientWalletAddress,
            amount: amountToSend, // Deducted amount
            seqno: seqno,
            sendMode: 3,
          }).send();

          console.log('Transaction sent to recipient wallet:', transfer);
          ctx.reply(`Payment received and sent to recipient wallet: ${recipientWalletAddress}`);
        } catch (sendError) {
          console.error('Error sending transaction to recipient wallet:', sendError);
          ctx.reply('Error occurred while sending funds to recipient wallet.');
        }
      }
    } catch (error) {
      console.error('Error checking balance:', error);
    }
  }, 2000);

  setTimeout(() => {
    clearInterval(intervalId);
    console.log('Monitoring timeout expired.');
    ctx.reply('Monitoring time expired. No payment received.');
  }, 15 * 60 * 1000);

  // Stop monitoring button
  ctx.reply('You can stop monitoring anytime using the button below.', {
    reply_markup: {
      inline_keyboard: [[{ text: 'Stop Monitoring', callback_data: 'stop_monitoring' }]]
    }
  });

  bot.action('stop_monitoring', (ctx) => {
    clearInterval(intervalId);
    console.log('User stopped monitoring manually.');
    ctx.reply('Monitoring stopped.');
  });
});

// Launch the bot
bot.launch();
console.log('Bot launched successfully.');

// Handle graceful shutdown
process.once('SIGINT', () => {
  console.log('SIGINT received. Stopping bot...');
  bot.stop('SIGINT');
});
process.once('SIGTERM', () => {
  console.log('SIGTERM received. Stopping bot...');
  bot.stop('SIGTERM');
});
