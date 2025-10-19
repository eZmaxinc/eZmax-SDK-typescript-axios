# DiscussionmessageRequestCompound

A Discussionmessage Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDiscussionmessageID** | **number** | The unique ID of the Discussionmessage | [optional] [default to undefined]
**fkiDiscussionID** | **number** | The unique ID of the Discussion | [default to undefined]
**fkiDiscussionmembershipIDActionrequired** | **number** | The unique ID of the Discussionmembership | [optional] [default to undefined]
**tDiscussionmessageContent** | **string** | The content of the Discussionmessage | [default to undefined]

## Example

```typescript
import { DiscussionmessageRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DiscussionmessageRequestCompound = {
    pkiDiscussionmessageID,
    fkiDiscussionID,
    fkiDiscussionmembershipIDActionrequired,
    tDiscussionmessageContent,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
