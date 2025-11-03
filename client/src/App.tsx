import { Box, useColorModeValue } from '@chakra-ui/react';
import { useState, useEffect } from 'react';
import UserRegistrationForm from './components/UserRegistrationForm';
import LoginForm from './components/LoginForm';
import Dashboard from './components/Dashboard';
import UserProfile from './components/UserProfile';
import UploadPage from './components/UploadPage';
import Navbar from './components/Navbar';
import SearchPage from './components/SearchPage/SearchPage';
import PlaybackPage from './components/PlaybackPage';

type AuthMode = 'login' | 'register' | 'dashboard' | 'profile' | 'upload' | 'search' | 'playback';

interface User {
  _id: string;
  username: string;
  email: string;
  createdAt: string;
  lastLogin: string;
}

function App() {
  const [authMode, setAuthMode] = useState<AuthMode>('login');
  const [user, setUser] = useState<User | null>(null);
  const [selectedVideo, setSelectedVideo] = useState<any | null>(null);
  const bg = useColorModeValue("gray.100", "gray.900");

  // Check if user is already logged in on app start
  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    const userInfo = localStorage.getItem('user_info');
    
    if (token && userInfo) {
      try {
        const parsedUser = JSON.parse(userInfo);
        setUser(parsedUser);
        setAuthMode('dashboard');
      } catch (err) {
        console.error('Error parsing user info:', err);
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_info');
      }
    }
  }, []);

  const handleLogin = (userData: User) => {
    setUser(userData);
    setAuthMode('dashboard');
  };

  const handleRegister = (userData: User) => {
    setUser(userData);
    setAuthMode('dashboard');
  };

  const handleLogout = () => {
    setUser(null);
    setAuthMode('login');
  };

  const handleViewProfile = () => {
    setAuthMode('profile');
  };

  const renderContent = () => {
    switch (authMode) {
      case 'login':
        return (
          <LoginForm 
            onLogin={handleLogin}
            onSwitchToRegister={() => setAuthMode('register')}
          />
        );
      case 'register':
        return (
          <UserRegistrationForm 
            onRegister={handleRegister}
            onSwitchToLogin={() => setAuthMode('login')}
          />
        );
      case 'dashboard':
        return user ? (
          <Dashboard 
            user={user}
            onLogout={handleLogout}
            onViewProfile={handleViewProfile}
            onGoToUpload={() => setAuthMode('upload')}
            onWatchVideos={() => setAuthMode('search')}
          />
        ) : null;
      case 'profile':
      return user ? (
        <UserProfile 
          user={user}
          onGoBack={() => setAuthMode('dashboard')}
        />
      ) : null;
      case 'upload':
        return user ? (
          <UploadPage
            user={user}
            onGoBack={() => setAuthMode('dashboard')}
          />
        ) : null;

      case 'search':
        return user ? (
          <SearchPage
            user={user}
            onGoBack={() => setAuthMode('dashboard')}
            onVideoSelect={(video) => {
              setSelectedVideo(video);
              setAuthMode('playback');
            }}
          />
        ) : null;

      case 'playback':
        return selectedVideo ? (
          <PlaybackPage
            video={selectedVideo}
            onGoBack={() => setAuthMode('search')}
            onGoDashboard={() => setAuthMode('dashboard')}
          />
        ) : null;

      default:
        return null;
    }
  };

  return (
    <Box minH="100vh" bg={bg}>
      {authMode !== 'dashboard' && <Navbar />}
      {renderContent()}
    </Box>
  );
}

export default App;