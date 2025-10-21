import { SimpleGrid, Heading, Box } from "@chakra-ui/react";
import VideoCard from "./VideoCard";
import { SAMPLE_VIDEOS } from "../../data/sampleVideo";
import type { SampleVideo } from "../../data/sampleVideo";

interface VideoGridProps {
  onVideoSelect?: (v: SampleVideo) => void;
}

const VideoGrid = ({ onVideoSelect }: VideoGridProps) => {
  const videos = SAMPLE_VIDEOS;
  return (
    <Box>
      <Heading size="lg" mb={6}>
        Recommended for you
      </Heading>
      <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
        {videos.map((v) => (
          <VideoCard key={v.id} video={v} onClick={onVideoSelect} />
        ))}
      </SimpleGrid>
    </Box>
  );
};

export default VideoGrid;