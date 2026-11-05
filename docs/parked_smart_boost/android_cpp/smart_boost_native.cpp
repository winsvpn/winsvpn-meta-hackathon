#include <jni.h>

#include <android/log.h>
#include <android/multinetwork.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

std::vector<int64_t> copyLongArray(JNIEnv* env, jlongArray array) {
    const jsize length = env->GetArrayLength(array);
    std::vector<int64_t> out(static_cast<size_t>(length));
    if (length > 0) {
        env->GetLongArrayRegion(array, 0, length, reinterpret_cast<jlong*>(out.data()));
    }
    return out;
}

std::vector<int32_t> copyIntArray(JNIEnv* env, jintArray array) {
    const jsize length = env->GetArrayLength(array);
    std::vector<int32_t> out(static_cast<size_t>(length));
    if (length > 0) {
        env->GetIntArrayRegion(array, 0, length, reinterpret_cast<jint*>(out.data()));
    }
    return out;
}

int64_t clampPositive(int64_t value, int64_t fallback) {
    return value > 0 ? value : fallback;
}

std::string javaStringToUtf8(JNIEnv* env, jstring value) {
    if (value == nullptr) {
        return {};
    }
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) {
        return {};
    }
    std::string out(chars);
    env->ReleaseStringUTFChars(value, chars);
    return out;
}

std::string errnoMessage(const char* operation) {
    std::ostringstream out;
    out << operation << " failed errno=" << errno << " " << std::strerror(errno);
    return out.str();
}

void closeQuietly(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

}  // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_wins_1vpn_SmartBoostNative_availableNative(JNIEnv*, jobject) {
    return JNI_TRUE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_wins_1vpn_SmartBoostNative_version(JNIEnv* env, jobject) {
    return env->NewStringUTF("wins-smart-boost-native-v8.15-probe+scheduler");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_wins_1vpn_SmartBoostNative_probeSocketBindings(
    JNIEnv* env,
    jobject,
    jobject service,
    jstring host,
    jint port,
    jintArray ids,
    jlongArray networkHandles) {
    const jsize count = env->GetArrayLength(ids);
    if (count <= 0 || env->GetArrayLength(networkHandles) != count) {
        return env->NewStringUTF("error:invalid-path-arrays");
    }

    const std::string hostValue = javaStringToUtf8(env, host);
    if (hostValue.empty() || port <= 0 || port > 65535) {
        return env->NewStringUTF("error:invalid-endpoint");
    }

    const std::vector<int32_t> idValues = copyIntArray(env, ids);
    const std::vector<int64_t> handleValues = copyLongArray(env, networkHandles);

    jclass serviceClass = env->GetObjectClass(service);
    if (serviceClass == nullptr) {
        return env->NewStringUTF("error:service-class-unavailable");
    }
    jmethodID protectMethod = env->GetMethodID(serviceClass, "protect", "(I)Z");
    env->DeleteLocalRef(serviceClass);
    if (protectMethod == nullptr) {
        env->ExceptionClear();
        return env->NewStringUTF("error:vpn-protect-method-unavailable");
    }

    struct addrinfo hints {};
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo* results = nullptr;
    const std::string portValue = std::to_string(static_cast<int>(port));
    const int gai = getaddrinfo(hostValue.c_str(), portValue.c_str(), &hints, &results);
    if (gai != 0 || results == nullptr) {
        std::ostringstream out;
        out << "error:getaddrinfo " << gai_strerror(gai);
        return env->NewStringUTF(out.str().c_str());
    }

    int opened = 0;
    int bound = 0;
    std::string lastError;

    for (int i = 0; i < count; ++i) {
        int fd = -1;
        for (addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
            fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd < 0) {
                lastError = errnoMessage("socket");
                continue;
            }

            const int bufferSize = 4 * 1024 * 1024;
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));

            const jboolean protectedSocket = env->CallBooleanMethod(
                service,
                protectMethod,
                static_cast<jint>(fd));
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                closeQuietly(fd);
                freeaddrinfo(results);
                return env->NewStringUTF("error:vpn-protect-threw");
            }
            if (protectedSocket != JNI_TRUE) {
                closeQuietly(fd);
                freeaddrinfo(results);
                return env->NewStringUTF("error:vpn-protect-rejected");
            }

            const int64_t handle = handleValues[static_cast<size_t>(i)];
            if (handle > 0) {
                errno = 0;
                if (android_setsocknetwork(static_cast<net_handle_t>(handle), fd) != 0) {
                    lastError = errnoMessage("android_setsocknetwork");
                    closeQuietly(fd);
                    fd = -1;
                    continue;
                }
                ++bound;
            }

            errno = 0;
            if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
                lastError = errnoMessage("udp-connect");
                closeQuietly(fd);
                fd = -1;
                continue;
            }

            ++opened;
            closeQuietly(fd);
            fd = -1;
            break;
        }

        if (fd >= 0) {
            closeQuietly(fd);
        }

        if (opened < i + 1) {
            std::ostringstream out;
            out << "error:path=" << idValues[static_cast<size_t>(i)] << " " << lastError;
            freeaddrinfo(results);
            return env->NewStringUTF(out.str().c_str());
        }
    }

    freeaddrinfo(results);

    std::ostringstream out;
    out << "ok:native-v8-ready opened=" << opened << " bound=" << bound;
    __android_log_print(
        ANDROID_LOG_DEBUG,
        "WinsBoostNative",
        "%s endpoint=%s:%d",
        out.str().c_str(),
        hostValue.c_str(),
        static_cast<int>(port));
    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_wins_1vpn_SmartBoostNative_choosePathIndex(
    JNIEnv* env,
    jobject,
    jintArray ids,
    jlongArray rttsMs,
    jlongArray sentLoads,
    jlongArray capacitiesBps,
    jintArray failures,
    jlongArray rxAgesMs) {
    const jsize count = env->GetArrayLength(ids);
    if (count <= 0 ||
        env->GetArrayLength(rttsMs) != count ||
        env->GetArrayLength(sentLoads) != count ||
        env->GetArrayLength(capacitiesBps) != count ||
        env->GetArrayLength(failures) != count ||
        env->GetArrayLength(rxAgesMs) != count) {
        return -1;
    }

    const std::vector<int32_t> idValues = copyIntArray(env, ids);
    const std::vector<int64_t> rttValues = copyLongArray(env, rttsMs);
    const std::vector<int64_t> loadValues = copyLongArray(env, sentLoads);
    const std::vector<int64_t> capacityValues = copyLongArray(env, capacitiesBps);
    const std::vector<int32_t> failureValues = copyIntArray(env, failures);
    const std::vector<int64_t> rxAgeValues = copyLongArray(env, rxAgesMs);

    int bestIndex = -1;
    int64_t bestScore = std::numeric_limits<int64_t>::max();
    int64_t bestRtt = std::numeric_limits<int64_t>::max();

    for (int i = 0; i < count; ++i) {
        const int64_t rtt = std::clamp(clampPositive(rttValues[static_cast<size_t>(i)], 220), int64_t{20}, int64_t{5000});
        bestRtt = std::min(bestRtt, rtt);
    }

    const int64_t rttCeiling = std::max(bestRtt + 55, (bestRtt * 16) / 10);

    for (int i = 0; i < count; ++i) {
        const size_t index = static_cast<size_t>(i);
        const int64_t rtt = std::clamp(clampPositive(rttValues[index], 220), int64_t{20}, int64_t{5000});
        const int64_t load = std::max<int64_t>(0, loadValues[index]);
        const int64_t capacity = std::clamp(clampPositive(capacityValues[index], 25000000), int64_t{256000}, int64_t{10000000000LL});
        const int64_t failuresScore = std::max<int32_t>(0, failureValues[index]) * 125000LL;
        const int64_t rxAge = std::max<int64_t>(0, rxAgeValues[index]);
        const int64_t stalePenalty = rxAge > 3500 ? (rxAge - 3500) * 300 : 0;
        const int64_t rttPenalty = rtt > rttCeiling ? (rtt - rttCeiling) * 2600 : 0;
        const int64_t pathSpread = std::abs(idValues[index]) % 7;
        const int64_t capacityWeightedLoad = ((load + 1) * 1000000LL) / capacity;

        const int64_t score =
            (capacityWeightedLoad * std::max<int64_t>(35, rtt)) +
            failuresScore +
            stalePenalty +
            rttPenalty +
            pathSpread;

        if (bestIndex < 0 || score < bestScore ||
            (score == bestScore && rtt < rttValues[static_cast<size_t>(bestIndex)])) {
            bestScore = score;
            bestIndex = i;
        }
    }

    return static_cast<jint>(bestIndex);
}
