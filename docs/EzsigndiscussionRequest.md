# EzsigndiscussionRequest

An Ezsigndiscussion Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndiscussionID** | **number** | The unique ID of the Ezsigndiscussion | [optional] [default to undefined]
**fkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**iEzsigndiscussionPagenumber** | **number** | The page number in the Ezsigndocument for the Ezsigndiscussion | [default to undefined]
**iEzsigndiscussionX** | **number** | The x of the Ezsigndiscussion | [default to undefined]
**iEzsigndiscussionY** | **number** | The y of the Ezsigndiscussion | [default to undefined]
**objDiscussion** | [**DiscussionRequest**](DiscussionRequest.md) |  | [default to undefined]

## Example

```typescript
import { EzsigndiscussionRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndiscussionRequest = {
    pkiEzsigndiscussionID,
    fkiEzsigndocumentID,
    iEzsigndiscussionPagenumber,
    iEzsigndiscussionX,
    iEzsigndiscussionY,
    objDiscussion,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
