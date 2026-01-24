# SignatureResponseV3

A Signature Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSignatureID** | **number** | The unique ID of the Signature | [default to undefined]
**fkiFontID** | **number** | The unique ID of the Font | [default to undefined]
**eSignaturePreference** | [**FieldESignaturePreference**](FieldESignaturePreference.md) |  | [default to undefined]
**bSignatureSvg** | **boolean** | Whether the signature has a SVG or not | [default to undefined]
**bSignatureSvginitials** | **boolean** | Whether the initials has a SVG or not | [default to undefined]

## Example

```typescript
import { SignatureResponseV3 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SignatureResponseV3 = {
    pkiSignatureID,
    fkiFontID,
    eSignaturePreference,
    bSignatureSvg,
    bSignatureSvginitials,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
