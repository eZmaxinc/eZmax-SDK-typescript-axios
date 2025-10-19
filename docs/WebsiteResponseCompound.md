# WebsiteResponseCompound

A Website Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiWebsiteID** | **number** | The unique ID of the Website Default | [default to undefined]
**fkiWebsitetypeID** | **number** | The unique ID of the Websitetype.  Valid values:  |Value|Description| |-|-| |1|Website| |2|Twitter| |3|Facebook| |4|Survey| | [default to undefined]
**sWebsiteAddress** | **string** | The URL of the website. | [default to undefined]

## Example

```typescript
import { WebsiteResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebsiteResponseCompound = {
    pkiWebsiteID,
    fkiWebsitetypeID,
    sWebsiteAddress,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
