/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ApikeyCreateObjectV2ResponseAllOf } from './apikey-create-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { ApikeyCreateObjectV2ResponseMPayload } from './apikey-create-object-v2-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

import { DefaultObject } from '../base'

/**
 * @type ApikeyCreateObjectV2Response
 * Response for POST /2/object/apikey
 * @export
 */
export type ApikeyCreateObjectV2Response = ApikeyCreateObjectV2ResponseAllOf & CommonResponse;


/**
 * @export 
 * A ApikeyCreateObjectV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectApikeyCreateObjectV2Response
 */
export class DefaultObjectApikeyCreateObjectV2Response extends DefaultObject {
   mPayload:Partial<ApikeyCreateObjectV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


