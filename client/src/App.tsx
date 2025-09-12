import { Box, useColorModeValue } from '@chakra-ui/react';
import { useState, useEffect } from 'react';
import UserRegistrationForm from './components/UserRegistrationForm';
import LoginForm from './components/LoginForm';
import Dashboard from './components/Dashboard';
import Navbar from './components/Navbar';

type AuthMode = 'login' | 'register' | 'dashboard';

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