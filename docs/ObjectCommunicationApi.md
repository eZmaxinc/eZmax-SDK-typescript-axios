# ObjectCommunicationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**communicationGetCommunicationBodyV1**](#communicationgetcommunicationbodyv1) | **GET** /1/object/communication/{pkiCommunicationID}/getCommunicationBody | Retrieve the communication body|
|[**communicationGetDocumenttypechecklistV1**](#communicationgetdocumenttypechecklistv1) | **GET** /1/object/communication/{pkiCommunicationID}/getDocumenttypechecklist | Retrieve Document type checklist|
|[**communicationSendV1**](#communicationsendv1) | **POST** /1/object/communication/send | Send a new Communication|
|[**communicationSyncDocumenttypechecklistV1**](#communicationsyncdocumenttypechecklistv1) | **POST** /1/object/communication/{pkiCommunicationID}/syncDocumenttypechecklist | Synchronize Document type checklist|

# **communicationGetCommunicationBodyV1**
> communicationGetCommunicationBodyV1()

This endpoint returns the communication body.

### Example

```typescript
import {
    ObjectCommunicationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommunicationApi(configuration);

let pkiCommunicationID: number; // (default to undefined)

const { status, data } = await apiInstance.communicationGetCommunicationBodyV1(
    pkiCommunicationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCommunicationID** | [**number**] |  | defaults to undefined|


### Return type

void (empty response body)

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**302** | The user has been redirected |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **communicationGetDocumenttypechecklistV1**
> CommunicationGetDocumenttypechecklistV1Response communicationGetDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectCommunicationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommunicationApi(configuration);

let pkiCommunicationID: number; // (default to undefined)

const { status, data } = await apiInstance.communicationGetDocumenttypechecklistV1(
    pkiCommunicationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCommunicationID** | [**number**] |  | defaults to undefined|


### Return type

**CommunicationGetDocumenttypechecklistV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **communicationSendV1**
> CommunicationSendV1Response communicationSendV1(communicationSendV1Request)

The endpoint allows to send one or many elements at once.

### Example

```typescript
import {
    ObjectCommunicationApi,
    Configuration,
    CommunicationSendV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommunicationApi(configuration);

let communicationSendV1Request: CommunicationSendV1Request; //

const { status, data } = await apiInstance.communicationSendV1(
    communicationSendV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **communicationSendV1Request** | **CommunicationSendV1Request**|  | |


### Return type

**CommunicationSendV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **communicationSyncDocumenttypechecklistV1**
> CommunicationSyncDocumenttypechecklistV1Response communicationSyncDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectCommunicationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommunicationApi(configuration);

let pkiCommunicationID: number; // (default to undefined)
let body: object; // (optional)

const { status, data } = await apiInstance.communicationSyncDocumenttypechecklistV1(
    pkiCommunicationID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiCommunicationID** | [**number**] |  | defaults to undefined|


### Return type

**CommunicationSyncDocumenttypechecklistV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

