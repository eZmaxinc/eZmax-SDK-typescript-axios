# EzsigndiscussionResponseCompound

A Ezsigndiscussion Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndiscussionID** | **number** | The unique ID of the Ezsigndiscussion | [default to undefined]
**fkiEzsignpageID** | **number** | The unique ID of the Ezsignpage | [default to undefined]
**fkiDiscussionID** | **number** | The unique ID of the Discussion | [default to undefined]
**iEzsigndiscussionX** | **number** | The x of the Ezsigndiscussion | [default to undefined]
**iEzsigndiscussionY** | **number** | The y of the Ezsigndiscussion | [default to undefined]
**iEzsigndiscussionPagenumber** | **number** | The page number in the Ezsigndocument for the Ezsigndiscussion | [default to undefined]
**objDiscussion** | [**DiscussionResponseCompound**](DiscussionResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { EzsigndiscussionResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndiscussionResponseCompound = {
    pkiEzsigndiscussionID,
    fkiEzsignpageID,
    fkiDiscussionID,
    iEzsigndiscussionX,
    iEzsigndiscussionY,
    iEzsigndiscussionPagenumber,
    objDiscussion,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
