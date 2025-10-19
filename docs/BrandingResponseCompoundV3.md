# BrandingResponseCompoundV3

A Branding Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiBrandingID** | **number** | The unique ID of the Branding | [default to undefined]
**fkiDomainID** | **number** | The unique ID of the Domain | [optional] [default to undefined]
**sDomainName** | **string** | The name of the Domain | [optional] [default to undefined]
**fkiEmailID** | **number** | The unique ID of the Email | [optional] [default to undefined]
**objBrandingDescription** | [**MultilingualBrandingDescription**](MultilingualBrandingDescription.md) |  | [default to undefined]
**sBrandingDescriptionX** | **string** | The Description of the Branding in the language of the requester | [default to undefined]
**sBrandingName** | **string** | The name of the Branding  This value will only be set if you wish to overwrite the default name. If you want to keep the default name, leave this property empty | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**eBrandingLogo** | [**FieldEBrandingLogo**](FieldEBrandingLogo.md) |  | [default to undefined]
**eBrandingAlignlogo** | [**FieldEBrandingAlignlogo**](FieldEBrandingAlignlogo.md) |  | [default to undefined]
**iBrandingColor** | **number** | The primary color. This is a RGB color converted into integer | [default to undefined]
**bBrandingIsactive** | **boolean** | Whether the Branding is active or not | [default to undefined]
**sBrandingLogourl** | **string** | The url of the picture used as logo in the Branding | [optional] [default to undefined]
**sBrandingLogoemailurl** | **string** | The url of the picture used in email as logo in the Branding | [optional] [default to undefined]
**sBrandingLogointerfaceurl** | **string** | The url of the picture used as logo in the Branding | [optional] [default to undefined]

## Example

```typescript
import { BrandingResponseCompoundV3 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BrandingResponseCompoundV3 = {
    pkiBrandingID,
    fkiDomainID,
    sDomainName,
    fkiEmailID,
    objBrandingDescription,
    sBrandingDescriptionX,
    sBrandingName,
    sEmailAddress,
    eBrandingLogo,
    eBrandingAlignlogo,
    iBrandingColor,
    bBrandingIsactive,
    sBrandingLogourl,
    sBrandingLogoemailurl,
    sBrandingLogointerfaceurl,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
