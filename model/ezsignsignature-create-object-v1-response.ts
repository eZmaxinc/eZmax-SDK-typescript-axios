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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureCreateObjectV1ResponseAllOf } from './ezsignsignature-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureCreateObjectV1ResponseMPayload } from './ezsignsignature-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignsignatureCreateObjectV1Response
 * Response for POST /1/object/ezsignsignature
 * @export
 */
export type EzsignsignatureCreateObjectV1Response = CommonResponse & EzsignsignatureCreateObjectV1ResponseAllOf;


/**
 * @export 
 * A EzsignsignatureCreateObjectV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignsignatureCreateObjectV1Response
 */
export class DefaultObjectEzsignsignatureCreateObjectV1Response extends DefaultObject {
   mPayload:Partial<EzsignsignatureCreateObjectV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


