/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionGetCurrentV1ResponseAllOf } from './activesession-get-current-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionGetCurrentV1ResponseMPayload } from './activesession-get-current-v1-response-mpayload';
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
 * @type ActivesessionGetCurrentV1Response
 * Response for GET /1/object/activesession/getCurrent
 * @export
 */
export type ActivesessionGetCurrentV1Response = ActivesessionGetCurrentV1ResponseAllOf & CommonResponse;


/**
 * @export 
 * A ActivesessionGetCurrentV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectActivesessionGetCurrentV1Response
 */
export class DefaultObjectActivesessionGetCurrentV1Response extends DefaultObject {
   mPayload:Partial<ActivesessionGetCurrentV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


