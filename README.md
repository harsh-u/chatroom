# RizzRoom - Voice Broadcasting MVP

A modern chat application with voice broadcasting capabilities similar to Google Meet.

## Features

- **Real-time Chat**: Instant messaging with emoji reactions
- **Voice Broadcasting**: Click the microphone button to broadcast your voice to all online users
- **WebRTC Audio**: Peer-to-peer audio streaming for low latency
- **User Management**: Admin panel for user approval and moderation
- **File Attachments**: Share files with S3 integration
- **Responsive Design**: Works on desktop and mobile devices

## Voice Broadcasting

The voice broadcasting feature allows users to:

1. **Start Broadcasting**: Click the 🎤 button to start broadcasting your voice
2. **Stop Broadcasting**: Click the button again or use the stop button to mute
3. **Listen to Others**: Automatically receive audio from other broadcasters
4. **Real-time Audio**: Low-latency voice communication using WebRTC

### How It Works

- Uses WebRTC for peer-to-peer audio streaming
- STUN servers for NAT traversal
- Socket.IO for signaling and coordination
- Automatic peer connection management

## Setup

### Prerequisites

- Python 3.7+
- MySQL database
- AWS S3 bucket (for file uploads)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd rizz-room
```

2. Install Python dependencies:
```bash
pip install flask flask-socketio eventlet flask-mysqldb flask-bcrypt flask-jwt-extended boto3 python-dotenv
```

3. Create a `.env` file with your configuration:
```env
DB_HOST=localhost
DB_USER=root
DB_PASS=your_password
DB_NAME=rizz_room
SECRET_KEY=your_secret_key
JWT_SECRET_KEY=your_jwt_secret
S3_BUCKET=your-s3-bucket
AWS_REGION=ap-south-1
```

4. Set up MySQL database:
```sql
CREATE DATABASE rizz_room CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

5. Run the application:
```bash
python app.py
```

The app will be available at `http://localhost:5000`

## Testing Voice Broadcasting

1. **Open the main app**: Navigate to `http://localhost:5000`
2. **Register/Login**: Create an account or sign in
3. **Start Broadcasting**: Click the 🎤 button in the chat header
4. **Allow Microphone**: Grant microphone access when prompted
5. **Test with Multiple Users**: Open multiple browser tabs/windows to test

### Test Page

For isolated testing, use the dedicated test page at `test_audio.html`:
- Simple interface for testing audio functionality
- Real-time logging of events
- Connection status monitoring

## Technical Details

### WebRTC Implementation

- **ICE Servers**: Google STUN servers for NAT traversal
- **Peer Connections**: Dynamic creation and management
- **Audio Tracks**: Microphone input to peer connections
- **Signaling**: Socket.IO events for WebRTC handshake

### Socket.IO Events

- `audio:join` - User joins audio room
- `audio:leave` - User leaves audio room
- `audio:start_broadcast` - User starts broadcasting
- `audio:stop_broadcast` - User stops broadcasting
- `audio:offer` - WebRTC offer
- `audio:answer` - WebRTC answer
- `audio:ice_candidate` - ICE candidate exchange

### Security Features

- JWT authentication for API endpoints
- Microphone permission handling
- User role-based access control
- Input validation and sanitization

## Browser Compatibility

- Chrome 66+ (recommended)
- Firefox 60+
- Safari 11+
- Edge 79+

**Note**: HTTPS is required for microphone access in production environments.

## Troubleshooting

### Common Issues

1. **Microphone Access Denied**
   - Check browser permissions
   - Ensure HTTPS in production
   - Try refreshing the page

2. **Audio Not Working**
   - Check browser console for errors
   - Verify WebRTC support
   - Check firewall/network settings

3. **Connection Issues**
   - Verify Socket.IO server is running
   - Check network connectivity
   - Review STUN server configuration

### Debug Mode

Enable debug logging in the browser console:
```javascript
localStorage.setItem('debug', 'socket.io-client:*');
```

## Future Enhancements

- Video broadcasting support
- Screen sharing
- Recording capabilities
- Advanced audio controls (mute, volume)
- Room-based audio channels
- Audio quality settings

## License

This project is licensed under the MIT License.
