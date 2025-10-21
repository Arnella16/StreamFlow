import React, { useRef, useEffect, useState } from "react";
import {
  Box,
  Container,
  Heading,
  SimpleGrid,
  Image,
  Text,
  AspectRatio,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalBody,
  ModalCloseButton,
  useColorModeValue,
  Button,
  VStack,
} from "@chakra-ui/react";

type Video = {
  id: string;
  title: string;
  thumbnail: string;
  src: string;
  channel?: string;
  views?: string;
  duration?: string;
};

// sample videos (replace with DB data later)
const SAMPLE_VIDEOS: Video[] = [
  {
    id: "1",
    title: "Big Buck Bunny — Sample",
    thumbnail: "https://picsum.photos/seed/1/640/360",
    src: "https://www.w3schools.com/html/mov_bbb.mp4",
    channel: "Sample Channel",
    views: "1.2M",
    duration: "10:34",
  },
  {
    id: "2",
    title: "Sample Clip 2",
    thumbnail: "https://picsum.photos/seed/2/640/360",
    src: "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    channel: "Demo Channel",
    views: "856K",
    duration: "02:12",
  },
  {
    id: "3",
    title: "Sample Clip 3",
    thumbnail: "https://picsum.photos/seed/3/640/360",
    src: "https://www.w3schools.com/html/mov_bbb.mp4",
    channel: "Demo Channel",
    views: "623K",
    duration: "08:40",
  },
  {
    id: "4",
    title: "Sample Clip 4",
    thumbnail: "https://picsum.photos/seed/4/640/360",
    src: "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    channel: "Demo Channel",
    views: "945K",
    duration: "05:20",
  },
];

const PlaybackPage: React.FC = () => {
  const [videos] = useState<Video[]>(SAMPLE_VIDEOS);
  const [selected, setSelected] = useState<Video | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const bg = useColorModeValue("gray.50", "gray.900");
  const cardBg = useColorModeValue("white", "gray.800");
  const border = useColorModeValue("gray.200", "gray.700");

  useEffect(() => {
    // when modal opens try to play
    if (selected && videoRef.current) {
      // attempt to play (click was user gesture)
      videoRef.current.currentTime = 0;
      const p = videoRef.current.play();
      if (p && typeof p.catch === "function") p.catch(() => {});
    } else {
      // pause when closed
      videoRef.current?.pause();
    }
  }, [selected]);

  return (
    <Box minH="100vh" bg={bg} pb={8}>
      <Container maxW="7xl" pt={6}>
        <Heading mb={6}>Playback — Click to Play</Heading>

        <SimpleGrid columns={{ base: 1, sm: 2, md: 3 }} spacing={6}>
          {videos.map((v) => (
            <Box
              key={v.id}
              bg={cardBg}
              borderWidth="1px"
              borderColor={border}
              borderRadius="md"
              overflow="hidden"
              cursor="pointer"
              boxShadow="md"
              onClick={() => setSelected(v)}
              transition="transform 0.15s ease"
              _hover={{ transform: "translateY(-4px)" }}
            >
              <AspectRatio ratio={16 / 9}>
                <Image src={v.thumbnail} alt={v.title} objectFit="cover" />
              </AspectRatio>

              <Box p={3}>
                <Text fontWeight="semibold" noOfLines={2}>
                  {v.title}
                </Text>
                <VStack spacing={0} align="start" mt={2}>
                  <Text fontSize="sm" color="gray.500">
                    {v.channel} • {v.views} views
                  </Text>
                </VStack>
              </Box>
            </Box>
          ))}
        </SimpleGrid>
      </Container>

      {/* Modal player */}
      <Modal isOpen={Boolean(selected)} onClose={() => setSelected(null)} size="6xl" isCentered>
        <ModalOverlay bg="blackAlpha.700" />
        <ModalContent bg="transparent" boxShadow="none" maxW="90vw">
          <ModalCloseButton color="white" zIndex={2} />
          <ModalBody p={0} display="flex" justifyContent="center" alignItems="center">
            <Box w={{ base: "100%", md: "80%" }} bg="black" borderRadius="md" overflow="hidden">
              {/* video element */}
              {selected && (
                <AspectRatio ratio={16 / 9} bg="black">
                  <video
                    ref={videoRef}
                    src={selected.src}
                    controls
                    style={{ width: "100%", height: "100%", backgroundColor: "black" }}
                  />
                </AspectRatio>
              )}

              {/* title & actions */}
              {selected && (
                <Box p={4} bg={useColorModeValue("white", "gray.800")}>
                  <Text fontSize="lg" fontWeight="semibold">
                    {selected.title}
                  </Text>
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    {selected.channel} • {selected.views} views
                  </Text>
                </Box>
              )}
            </Box>
          </ModalBody>
        </ModalContent>
      </Modal>
    </Box>
  );
};

export default PlaybackPage;