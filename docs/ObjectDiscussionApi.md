# ObjectDiscussionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**discussionChatV1**](#discussionchatv1) | **POST** /1/object/discussion/chat | Have a Discussion with the AI Chatbot|
|[**discussionCreateObjectV1**](#discussioncreateobjectv1) | **POST** /1/object/discussion | Create a new Discussion|
|[**discussionDeleteObjectV1**](#discussiondeleteobjectv1) | **DELETE** /1/object/discussion/{pkiDiscussionID} | Delete an existing Discussion|
|[**discussionGetObjectV2**](#discussiongetobjectv2) | **GET** /2/object/discussion/{pkiDiscussionID} | Retrieve an existing Discussion|
|[**discussionPatchObjectV1**](#discussionpatchobjectv1) | **PATCH** /1/object/discussion/{pkiDiscussionID} | Patch an existing Discussion|
|[**discussionUpdateDiscussionreadstatusV1**](#discussionupdatediscussionreadstatusv1) | **POST** /1/object/discussion/{pkiDiscussionID}/updateDiscussionreadstatus | Update the read status of the discussion|

# **discussionChatV1**
> DiscussionChatV1200Response discussionChatV1(discussionChatV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectDiscussionApi,
    Configuration,
    DiscussionChatV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionApi(configuration);

let discussionChatV1Request: DiscussionChatV1Request; //

const { status, data } = await apiInstance.discussionChatV1(
    discussionChatV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **discussionChatV1Request** | **DiscussionChatV1Request**|  | |


### Return type

**DiscussionChatV1200Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: text/event-stream


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **discussionCreateObjectV1**
> DiscussionCreateObjectV1Response discussionCreateObjectV1(discussionCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectDiscussionApi,
    Configuration,
    DiscussionCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionApi(configuration);

let discussionCreateObjectV1Request: DiscussionCreateObjectV1Request; //

const { status, data } = await apiInstance.discussionCreateObjectV1(
    discussionCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **discussionCreateObjectV1Request** | **DiscussionCreateObjectV1Request**|  | |


### Return type

**DiscussionCreateObjectV1Response**

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

# **discussionDeleteObjectV1**
> DiscussionDeleteObjectV1Response discussionDeleteObjectV1()



### Example

```typescript
import {
    ObjectDiscussionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionApi(configuration);

let pkiDiscussionID: number; //The unique ID of the Discussion (default to undefined)

const { status, data } = await apiInstance.discussionDeleteObjectV1(
    pkiDiscussionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDiscussionID** | [**number**] | The unique ID of the Discussion | defaults to undefined|


### Return type

**DiscussionDeleteObjectV1Response**

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

# **discussionGetObjectV2**
> DiscussionGetObjectV2Response discussionGetObjectV2()



### Example

```typescript
import {
    ObjectDiscussionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionApi(configuration);

let pkiDiscussionID: number; //The unique ID of the Discussion (default to undefined)

const { status, data } = await apiInstance.discussionGetObjectV2(
    pkiDiscussionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDiscussionID** | [**number**] | The unique ID of the Discussion | defaults to undefined|


### Return type

**DiscussionGetObjectV2Response**

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

# **discussionPatchObjectV1**
> DiscussionPatchObjectV1Response discussionPatchObjectV1(discussionPatchObjectV1Request)



### Example

```typescript
import {
    ObjectDiscussionApi,
    Configuration,
    DiscussionPatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionApi(configuration);

let pkiDiscussionID: number; //The unique ID of the Discussion (default to undefined)
let discussionPatchObjectV1Request: DiscussionPatchObjectV1Request; //

const { status, data } = await apiInstance.discussionPatchObjectV1(
    pkiDiscussionID,
    discussionPatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **discussionPatchObjectV1Request** | **DiscussionPatchObjectV1Request**|  | |
| **pkiDiscussionID** | [**number**] | The unique ID of the Discussion | defaults to undefined|


### Return type

**DiscussionPatchObjectV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **discussionUpdateDiscussionreadstatusV1**
> DiscussionUpdateDiscussionreadstatusV1Response discussionUpdateDiscussionreadstatusV1(discussionUpdateDiscussionreadstatusV1Request)


### Example

```typescript
import {
    ObjectDiscussionApi,
    Configuration,
    DiscussionUpdateDiscussionreadstatusV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionApi(configuration);

let pkiDiscussionID: number; // (default to undefined)
let discussionUpdateDiscussionreadstatusV1Request: DiscussionUpdateDiscussionreadstatusV1Request; //

const { status, data } = await apiInstance.discussionUpdateDiscussionreadstatusV1(
    pkiDiscussionID,
    discussionUpdateDiscussionreadstatusV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **discussionUpdateDiscussionreadstatusV1Request** | **DiscussionUpdateDiscussionreadstatusV1Request**|  | |
| **pkiDiscussionID** | [**number**] |  | defaults to undefined|


### Return type

**DiscussionUpdateDiscussionreadstatusV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

