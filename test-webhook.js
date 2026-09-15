const crypto = require('crypto');

const secret = 'super_secret_key_123';

const body = JSON.stringify({
  event: 'payment.success',
  id: 'pay_12345',
  amount: 500,
  currency: 'INR'
});

const signature = crypto
  .createHmac('sha256', secret)
  .update(body)
  .digest('hex');

console.log('Body:');
console.log(body);

console.log('\nSignature:');
console.log(signature);