import Header from "./Header";
import Hero from "./Hero";
import VideoGrid from "./VideoGrid";
import { Container, Box, Button } from "@chakra-ui/react";
import { ArrowLeft } from "lucide-react";

interface User {
  _id: string;
  username: string;
  email: string;
  createdAt: string;
  lastLogin: string;
}

interface PlaybackPageProps {
  user: User;
  onGoBack?: () => void;
}

const PlaybackPage = ({ user, onGoBack }: PlaybackPageProps) => {
  return (
    <Box minH="100vh" bg="transparent">
      <Header />
      <Container maxW="7xl" px={{ base: 4, md: 8 }} py={{ base: 4, md: 6 }}>
        {onGoBack && (
          <Box mb={4} display="flex" justifyContent="flex-start">
            <Button
              onClick={onGoBack}
              leftIcon={<ArrowLeft size={16} />}
              variant="ghost"
              size="sm"
              colorScheme="blue"
            >
              Back to Dashboard
            </Button>
          </Box>
        )}

        <Box mb={8}>
          <Hero />
        </Box>

        <main>
          <VideoGrid />
        </main>
      </Container>
    </Box>
  );
};

export default PlaybackPage;