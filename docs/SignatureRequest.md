# SignatureRequest

A Signature Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSignatureID** | **number** | The unique ID of the Signature | [optional] [default to undefined]
**fkiFontID** | **number** | The unique ID of the Font | [default to undefined]
**eSignaturePreference** | [**FieldESignaturePreference**](FieldESignaturePreference.md) |  | [default to undefined]
**tSignatureSvg** | **string** | The svg of the Signature | [optional] [default to undefined]
**tSignatureSvginitials** | **string** | The svg of the Initials | [optional] [default to undefined]

## Example

```typescript
import { SignatureRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SignatureRequest = {
    pkiSignatureID,
    fkiFontID,
    eSignaturePreference,
    tSignatureSvg,
    tSignatureSvginitials,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
