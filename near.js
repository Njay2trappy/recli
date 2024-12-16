// Import required modules
const { Telegraf } = require('telegraf');
const { connect, keyStores, utils, transactions } = require('near-api-js');
const axios = require('axios');

// Initialize the bot
const bot = new Telegraf('7679256143:AAHNnB6vieOmKnD1lm2oRMS7UNafThA2FAs');

// NEAR configuration for Mainnet
const keyStore = new keyStores.InMemoryKeyStore();
const nearConfig = {
  networkId: 'mainnet',
  nodeUrl: 'https://rpc.mainnet.near.org',
  walletUrl: 'https://wallet.mainnet.near.org',
  helperUrl: 'https://helper.mainnet.near.org',
  keyStore,
};

let near;
let depositAccount = null;
let recipientWallet = null;
let depositAmountInNear = null;
let pendingAction = null;

// Helper function to initialize NEAR connection
async function initializeNear() {
  near = await connect(nearConfig);
}

// Helper function to generate a new NEAR account
async function generateNearAccount() {
  const keyPair = utils.KeyPair.fromRandom('ed25519');
  const accountId = `bot-${Date.now()}.near`; // Replace with your sub-account logic
  const publicKey = keyPair.getPublicKey().toString();
  const privateKey = keyPair.secretKey;

  console.log(`Generated NEAR Wallet Address (Account ID): ${accountId}`);
  console.log(`Public Key: ${publicKey}`);
  console.log(`Private Key: ${privateKey}`);

  // Fund the new account using a funded account
  const funderAccountId = 'YOUR_FUNDED_ACCOUNT.near'; // Replace with your funded account
  const funderAccount = await near.account(funderAccountId);

  try {
    const initialBalance = utils.format.parseNearAmount('0.1'); // Minimum balance to create the account
    await funderAccount.createAccount(accountId, publicKey, initialBalance);
    console.log(`Account ${accountId} created and funded with 0.1 NEAR.`);
  } catch (error) {
    console.error(`Error funding account ${accountId}:`, error);
    throw new Error('Failed to fund the new account.');
  }

  return { accountId, publicKey, privateKey };
}

// Helper function to convert USD to NEAR
async function convertToNear(amountInUSD) {
  console.log(`Converting ${amountInUSD} USD to NEAR...`);
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=near&vs_currencies=usd');
    const nearPriceInUSD = response.data.near.usd;
    console.log(`Conversion rate fetched: 1 NEAR = ${nearPriceInUSD} USD`);
    return amountInUSD / nearPriceInUSD;
  } catch (error) {
    console.error('Error fetching conversion rate from CoinGecko API:', error);
    return null;
  }
}

// Helper function to monitor deposits
async function startMonitoring(ctx) {
  const intervalId = setInterval(async () => {
    try {
      const account = await near.account(depositAccount.accountId);
      const balance = utils.format.formatNearAmount((await account.getAccountBalance()).available);
      console.log(`Current balance for ${depositAccount.accountId}: ${balance} NEAR`);

      if (parseFloat(balance) >= depositAmountInNear) {
        clearInterval(intervalId);
        ctx.reply('Deposit confirmed. Transferring funds to the recipient wallet...');
        console.log('Deposit confirmed.');

        // Transfer funds to the recipient
        try {
          const transferAmount = utils.format.parseNearAmount(
            (parseFloat(balance) - 0.01).toFixed(6)
          ); // Subtract 0.01 NEAR for transaction fees

          await account.sendMoney(recipientWallet, transferAmount);
          ctx.reply('Funds transferred successfully!');
        } catch (transferError) {
          console.error('Error transferring funds:', transferError);
          ctx.reply('Error transferring funds. Please contact support.');
        }
      }
    } catch (monitorError) {
      console.error('Error monitoring wallet:', monitorError);
    }
  }, 2000);

  // Stop monitoring button
  ctx.reply('You can stop monitoring anytime using the button below.', {
    reply_markup: {
      inline_keyboard: [[{ text: 'Stop Monitoring', callback_data: 'stop_monitoring' }]],
    },
  });

  bot.action('stop_monitoring', (ctx) => {
    clearInterval(intervalId);
    ctx.reply('Monitoring stopped.');
  });
}

// Start bot command
bot.start(async (ctx) => {
  console.log('Bot started by user:', ctx.from.id);
  await initializeNear();
  ctx.reply('Welcome! Use this bot to process NEAR payments.', {
    reply_markup: {
      inline_keyboard: [[{ text: 'Set Recipient Wallet', callback_data: 'set_recipient_wallet' }]],
    },
  });
});

// Bot command to handle recipient wallet
bot.action('set_recipient_wallet', async (ctx) => {
  pendingAction = 'set_recipient_wallet';
  ctx.reply('Enter the recipient wallet address:');
});

bot.action('set_deposit_amount', async (ctx) => {
  pendingAction = 'set_deposit_amount';
  ctx.reply('Enter the deposit amount in USD:');
});

bot.on('text', async (ctx) => {
  if (pendingAction === 'set_recipient_wallet') {
    recipientWallet = ctx.message.text;
    console.log(`Recipient wallet address set: ${recipientWallet}`);
    ctx.reply(`Recipient wallet address saved: ${recipientWallet}. Now, set the deposit amount.`, {
      reply_markup: {
        inline_keyboard: [[{ text: 'Set Deposit Amount', callback_data: 'set_deposit_amount' }]],
      },
    });
    pendingAction = null;
  } else if (pendingAction === 'set_deposit_amount') {
    const depositAmountInUSD = parseFloat(ctx.message.text);
    if (isNaN(depositAmountInUSD)) {
      ctx.reply('Please enter a valid deposit amount in USD.');
      return;
    }

    depositAmountInNear = await convertToNear(depositAmountInUSD);
    if (!depositAmountInNear) {
      ctx.reply('Error converting amount. Please try again later.');
      return;
    }

    ctx.reply(`Your deposit wallet is being generated. Please wait...`);

    depositAccount = await generateNearAccount();
    ctx.reply(`Deposit wallet generated successfully:

Account ID: ${depositAccount.accountId}
Public Key: ${depositAccount.publicKey}
Private Key: ${depositAccount.privateKey}

Keep your private key secure.

Deposit approximately ${depositAmountInNear.toFixed(6)} NEAR to the above address.`, {
      reply_markup: {
        inline_keyboard: [[{ text: 'Confirm Deposit', callback_data: 'confirm_deposit' }]],
      },
    });
    pendingAction = null;
  }
});

// Bot command to confirm deposit and start monitoring
bot.action('confirm_deposit', async (ctx) => {
  if (!depositAccount || !depositAmountInNear) {
    ctx.reply('No deposit wallet or amount set. Please start the process again.');
    return;
  }

  ctx.reply(`Monitoring for a deposit to the wallet:

Account ID: ${depositAccount.accountId}`);
  startMonitoring(ctx);
});

// Launch the bot
bot.launch();
console.log('NEAR Payment Bot launched successfully.');

// Handle graceful shutdown
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
