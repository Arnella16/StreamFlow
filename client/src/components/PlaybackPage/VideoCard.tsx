import { Box, Image, Text, Flex, useColorModeValue } from "@chakra-ui/react";
import { Play } from "lucide-react";

interface VideoCardProps {
  thumbnail: string;
  title: string;
  channel: string;
  views: string;
  timestamp: string;
}

const VideoCard = ({ thumbnail, title, channel, views, timestamp }: VideoCardProps) => {
  return (
    <Box borderRadius="md" overflow="hidden" bg={useColorModeValue("white", "gray.800")} boxShadow="md" borderWidth="1px" borderColor={useColorModeValue("gray.100", "gray.700")}>
      <Box position="relative" w="100%" h="0" paddingBottom="56.25%">
        <Image src={thumbnail} alt={title} objectFit="cover" position="absolute" top={0} left={0} w="100%" h="100%" />
        <Box position="absolute" bottom={2} right={2} bg={useColorModeValue("whiteAlpha.900", "blackAlpha.700")} px={2} py={1} borderRadius="sm" fontSize="xs">
          {timestamp}
        </Box>
        <Box position="absolute" inset={0} display="flex" alignItems="center" justifyContent="center" opacity={0} transition="opacity 0.2s" _hover={{ opacity: 1, bg: "blackAlpha.300" }}>
          <Box bg="blue.500" borderRadius="full" p={3}>
            <Play color="white" />
          </Box>
        </Box>
      </Box>

      <Box p={4}>
        <Text fontWeight="semibold" noOfLines={2} mb={2}>
          {title}
        </Text>
        <Flex align="center" justify="space-between" gap={3}>
          <Text fontSize="sm" color={useColorModeValue("gray.600", "gray.400")}>{channel}</Text>
          <Text fontSize="sm" color={useColorModeValue("gray.600", "gray.400")}>{views} views</Text>
        </Flex>
      </Box>
    </Box>
  );
};

export default VideoCard;