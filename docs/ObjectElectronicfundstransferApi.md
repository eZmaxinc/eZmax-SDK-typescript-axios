# ObjectElectronicfundstransferApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**electronicfundstransferGetCommunicationCountV1**](#electronicfundstransfergetcommunicationcountv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationCount | Retrieve Communication count|
|[**electronicfundstransferGetCommunicationListV1**](#electronicfundstransfergetcommunicationlistv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationList | Retrieve Communication list|
|[**electronicfundstransferGetCommunicationrecipientsV1**](#electronicfundstransfergetcommunicationrecipientsv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationrecipients | Retrieve Electronicfundstransfer\&#39;s Communicationrecipient|
|[**electronicfundstransferGetCommunicationsendersV1**](#electronicfundstransfergetcommunicationsendersv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationsenders | Retrieve Electronicfundstransfer\&#39;s Communicationsender|
|[**electronicfundstransferImportIntoEDMV1**](#electronicfundstransferimportintoedmv1) | **POST** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/importIntoEDM | Import attachments into the Electronicfundstransfer|

# **electronicfundstransferGetCommunicationCountV1**
> ElectronicfundstransferGetCommunicationCountV1Response electronicfundstransferGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetCommunicationCountV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetCommunicationCountV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **electronicfundstransferGetCommunicationListV1**
> ElectronicfundstransferGetCommunicationListV1Response electronicfundstransferGetCommunicationListV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetCommunicationListV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetCommunicationListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **electronicfundstransferGetCommunicationrecipientsV1**
> ElectronicfundstransferGetCommunicationrecipientsV1Response electronicfundstransferGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetCommunicationrecipientsV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetCommunicationrecipientsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **electronicfundstransferGetCommunicationsendersV1**
> ElectronicfundstransferGetCommunicationsendersV1Response electronicfundstransferGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetCommunicationsendersV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetCommunicationsendersV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **electronicfundstransferImportIntoEDMV1**
> ElectronicfundstransferImportIntoEDMV1Response electronicfundstransferImportIntoEDMV1(electronicfundstransferImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration,
    ElectronicfundstransferImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)
let electronicfundstransferImportIntoEDMV1Request: ElectronicfundstransferImportIntoEDMV1Request; //

const { status, data } = await apiInstance.electronicfundstransferImportIntoEDMV1(
    pkiElectronicfundstransferID,
    electronicfundstransferImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **electronicfundstransferImportIntoEDMV1Request** | **ElectronicfundstransferImportIntoEDMV1Request**|  | |
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferImportIntoEDMV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

