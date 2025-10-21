import { Box, Stack, Heading, Text, Button, Icon, useColorModeValue } from "@chakra-ui/react";
import { Play } from "lucide-react";
import heroImage from "../../assets/hero-bg.jpg";

const Hero = () => {
  const overlay = useColorModeValue("linear-gradient(to top, rgba(255,255,255,0.85), rgba(255,255,255,0.25))", "linear-gradient(to top, rgba(0,0,0,0.65), rgba(0,0,0,0.25))");
  const textColor = useColorModeValue("gray.800", "white");

  return (
    <Box
      w="full"
      h={{ base: "320px", md: "420px", lg: "500px" }}
      borderRadius="lg"
      overflow="hidden"
      position="relative"
      bgImage={`url(${heroImage})`}
      bgPos="center"
      bgSize="cover"
    >
      <Box position="absolute" inset={0} bg={overlay} />
      <Stack
        position="relative"
        zIndex={1}
        h="full"
        align="center"
        justify="center"
        textAlign="center"
        px={{ base: 4, md: 8 }}
      >
        <Heading as="h1" size={{ base: "lg", md: "2xl", lg: "4xl" }} color={textColor} mb={2}>
          Watch Amazing Content
        </Heading>
        <Text fontSize={{ base: "md", md: "lg" }} color={useColorModeValue("gray.700", "gray.200")} maxW="3xl">
          Discover thousands of videos from creators around the world
        </Text>
        <Button
          mt={4}
          size="lg"
          colorScheme="blue"
          leftIcon={<Icon as={Play} />}
          boxShadow="lg"
        >
          Start Watching
        </Button>
      </Stack>
    </Box>
  );
};

export default Hero;