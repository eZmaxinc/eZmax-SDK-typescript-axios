# CustomEzsignsignaturestatusResponse

A Ezsignsignaturestatus Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eEzsignsignaturestatusSteptype** | **string** | Type of step | [default to undefined]
**iEzsignsignaturestatusStep** | **number** | The step at which the Ezsignsigner will be invited to sign or fill the form fields | [default to undefined]
**iEzsignsignaturestatusTotal** | **number** | The total number of signature or form fields the Ezsignsigner must process at the current step | [default to undefined]
**iEzsignsignaturestatusSigned** | **number** | The number of signature or form fields the Ezsignsigner has already processed at the current step | [default to undefined]
**iEzsignsignaturestatusConditional** | **number** | The number of signature or form fields the Ezsignsigner need to sign or fill under current conditions. | [default to undefined]

## Example

```typescript
import { CustomEzsignsignaturestatusResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsignsignaturestatusResponse = {
    eEzsignsignaturestatusSteptype,
    iEzsignsignaturestatusStep,
    iEzsignsignaturestatusTotal,
    iEzsignsignaturestatusSigned,
    iEzsignsignaturestatusConditional,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
