import React, { createContext, useContext, useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from './AuthContext';
import toast from 'react-hot-toast';

const SocketContext = createContext();

export const useSocket = () => useContext(SocketContext);

export const SocketProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const { user, token } = useAuth();

  useEffect(() => {
    if (user && token) {
      const newSocket = io(process.env.REACT_APP_API_URL || 'http://localhost:5000', {
        auth: { token }
      });

      setSocket(newSocket);

      // Connection events
      newSocket.on('connect', () => {
        console.log('🔌 Connected to socket server');
      });

      newSocket.on('disconnect', () => {
        console.log('🔌 Disconnected from socket server');
      });

      // User presence
      newSocket.on('user:online', ({ userId, username }) => {
        setOnlineUsers(prev => [...prev, userId]);
        toast(`${username} is online`, {
          icon: '🟢',
          duration: 2000
        });
      });

      newSocket.on('user:offline', ({ userId, username }) => {
        setOnlineUsers(prev => prev.filter(id => id !== userId));
        toast(`${username} went offline`, {
          icon: '🔴',
          duration: 2000
        });
      });

      // Notifications
      newSocket.on('notification:new', (notification) => {
        switch (notification.type) {
          case 'mention':
            toast.custom((t) => (
              <div className="notification mention">
                <strong>🔔 {notification.from} mentioned you</strong>
                <p>in {notification.channel}</p>
              </div>
            ));
            break;
          case 'solution':
            toast.success('Your answer was marked as solution! +50 XP');
            break;
          default:
            break;
        }
      });

      // Typing indicators
      let typingTimeout;
      newSocket.on('typing:start', ({ userId, username }) => {
        // Show typing indicator in UI
        const typingElement = document.getElementById(`typing-${userId}`);
        if (typingElement) {
          typingElement.style.display = 'block';
        }
      });

      newSocket.on('typing:stop', ({ userId }) => {
        const typingElement = document.getElementById(`typing-${userId}`);
        if (typingElement) {
          typingElement.style.display = 'none';
        }
      });

      return () => {
        newSocket.close();
      };
    }
  }, [user, token]);

  const joinChannel = (channelId) => {
    if (socket) {
      socket.emit('channel:join', channelId);
    }
  };

  const leaveChannel = (channelId) => {
    if (socket) {
      socket.emit('channel:leave', channelId);
    }
  };

  const sendTyping = (channelId, isTyping) => {
    if (socket) {
      socket.emit(isTyping ? 'typing:start' : 'typing:stop', { channelId });
    }
  };

  const joinVoiceRoom = (roomId) => {
    if (socket) {
      socket.emit('voice:join', { roomId });
    }
  };

  const leaveVoiceRoom = (roomId) => {
    if (socket) {
      socket.emit('voice:leave', { roomId });
    }
  };

  const sendVoiceSignal = (to, signal) => {
    if (socket) {
      socket.emit('voice:signal', { to, signal });
    }
  };

  const value = {
    socket,
    onlineUsers,
    joinChannel,
    leaveChannel,
    sendTyping,
    joinVoiceRoom,
    leaveVoiceRoom,
    sendVoiceSignal,
    isUserOnline: (userId) => onlineUsers.includes(userId)
  };

  return (
    <SocketContext.Provider value={value}>
      {children}
    </SocketContext.Provider>
  );
};