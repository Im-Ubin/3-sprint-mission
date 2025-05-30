package com.sprint.mission.discodeit.service;

import com.sprint.mission.discodeit.entity.BinaryContent;
import com.sprint.mission.discodeit.dto.request.BinaryContentCreateRequest;

import java.util.List;
import java.util.UUID;

public interface BinaryContentService {
    BinaryContent create(BinaryContentCreateRequest binaryContentCreateRequest);
    BinaryContent find(UUID id);
    List<BinaryContent> findAll();
    void delete(UUID id);
}
