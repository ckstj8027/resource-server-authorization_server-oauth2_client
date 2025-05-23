package io.oauth2.sharedobject;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class MyInfo {
    private List<Photo> photos;
    private List<Friend> friends;
}
