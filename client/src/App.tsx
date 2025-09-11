import { Container, Box, useColorModeValue } from '@chakra-ui/react';
import UserRegistrationForm from './components/UserRegistrationForm';
import Navbar from './components/Navbar';

function App() {
  const bg = useColorModeValue("gray.100", "gray.900");

  return (
    <Box minH="100vh" bg={bg}>
      <Navbar />
      <Container
        maxW="2xl"
        display="flex"
        alignItems="center"
        justifyContent="center"
        minH="calc(100vh - 64px)" // 64px is the navbar height
        pt="64px"
      >
        <UserRegistrationForm />
      </Container>
    </Box>
  );
}

export default App;