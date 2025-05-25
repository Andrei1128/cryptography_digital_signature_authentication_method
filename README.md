# Digital Signature Authentication System

A secure application for creating and verifying digital signatures using RSA-2048 and SHA-256.

## Communication Between Two Users

### Scenario: Alice wants to send a signed message to Bob

#### Step 1: Initial Setup (Both Users)
1. Both Alice and Bob need to install the application following the Installation instructions above
2. Each user generates their own key pair:
   - Click "Generate New Keys"
   - Save both private and public keys securely
   - Keep the private key secure and never share it
   - The public key can be shared with others

#### Step 2: Key Exchange
1. Alice and Bob exchange their public keys through a secure channel
2. Each user loads the other's public key:
   - Click "Load Keys"
   - Select your own private key
   - Select the other person's public key

#### Step 3: Sending a Signed Message (Alice)
1. Alice opens the application and loads her keys
2. In the "Message" text box, Alice types her message
3. Alice clicks "Sign Message"
4. The signature appears in the "Signature" text box
5. Alice sends both the message and signature to Bob through any communication channel (email, chat, etc.)

#### Step 4: Verifying the Message (Bob)
1. Bob opens the application and loads his keys
2. Bob copies Alice's message into the "Message" text box
3. Bob copies Alice's signature into the "Signature" text box
4. Bob clicks "Verify Signature"
5. If the signature is valid, Bob knows:
   - The message came from Alice (authentication)
   - The message hasn't been modified (integrity)
   - Alice cannot deny sending the message (non-repudiation)

### Example Communication Flow

1. **Alice's Side:**
   ```
   Message: "Hello Bob, please transfer $100 to account 123456"
   Signature: [generated signature appears here]
   ```

2. **Bob's Side:**
   ```
   Message: "Hello Bob, please transfer $100 to account 123456"
   Signature: [paste Alice's signature here]
   Verification Result: Valid/Invalid
   ```

### Security Considerations for Two-User Communication

1. **Key Exchange Security**
   - Exchange public keys through a trusted channel
   - Verify the authenticity of received public keys
   - Consider using a trusted third party for key distribution

2. **Message Transmission**
   - The message and signature can be sent through any channel
   - The signature ensures message integrity regardless of transmission method
   - Consider encrypting sensitive messages in addition to signing them

3. **Verification Process**
   - Always verify signatures immediately upon receipt
   - Check the message context and sender
   - Keep a log of verified messages for record-keeping

4. **Key Management**
   - Each user should maintain their own private key securely
   - Public keys should be stored in a trusted location
   - Consider key rotation for long-term communication

### Common Two-User Scenarios

1. **Business Communication**
   - Signing contracts
   - Approving transactions
   - Authorizing actions

2. **Personal Communication**
   - Secure messaging
   - Document verification
   - Personal agreements

3. **Technical Communication**
   - Code signing
   - Configuration changes
   - System updates