import React, { useRef, useEffect, useState } from "react";
import Header from "./Header";
import Hero from "./Hero";
import VideoGrid from "./VideoGrid";
import {
  Container,
  Box,
  Button,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalBody,
  ModalCloseButton,
  AspectRatio,
  Text,
  useColorModeValue,
  Heading,
} from "@chakra-ui/react";
import { ArrowLeft } from "lucide-react";
import type { SampleVideo } from "../../data/sampleVideo";

interface User {
  _id: string;
  username: string;
  email: string;
  createdAt: string;
  lastLogin: string;
}

interface SearchPageProps {
  user?: User;
  onGoBack?: () => void;
}

const SearchPage: React.FC<SearchPageProps> = ({ user, onGoBack }) => {
  const [selected, setSelected] = useState<SampleVideo | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const bg = useColorModeValue("gray.50", "gray.900");

  useEffect(() => {
    if (selected && videoRef.current) {
      videoRef.current.currentTime = 0;
      const p = videoRef.current.play();
      if (p && typeof p.catch === "function") p.catch(() => {});
    } else {
      videoRef.current?.pause();
    }
  }, [selected]);

  return (
    <Box minH="100vh" bg={bg}>
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
          <Heading mb={6}>Search / Browse</Heading>
          <VideoGrid onVideoSelect={(v) => setSelected(v)} />
        </main>
      </Container>

      <Modal isOpen={Boolean(selected)} onClose={() => setSelected(null)} size="6xl" isCentered>
        <ModalOverlay bg="blackAlpha.700" />
        <ModalContent bg="transparent" boxShadow="none" maxW="90vw">
          <ModalCloseButton color="white" zIndex={2} />
          <ModalBody p={0} display="flex" justifyContent="center" alignItems="center">
            <Box w={{ base: "100%", md: "80%" }} bg="black" borderRadius="md" overflow="hidden">
              {selected && (
                <>
                  <AspectRatio ratio={16 / 9} bg="black">
                    <video
                      ref={videoRef}
                      src={selected.src}
                      controls
                      style={{ width: "100%", height: "100%", backgroundColor: "black" }}
                    />
                  </AspectRatio>

                  <Box p={4} bg={useColorModeValue("white", "gray.800")}>
                    <Text fontSize="lg" fontWeight="semibold">
                      {selected.title}
                    </Text>
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      {selected.channel} • {selected.views} views
                    </Text>
                  </Box>
                </>
              )}
            </Box>
          </ModalBody>
        </ModalContent>
      </Modal>
    </Box>
  );
};

export default SearchPage;