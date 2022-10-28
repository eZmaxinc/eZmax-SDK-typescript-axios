/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
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
import { EzsignbulksendsignermappingCreateObjectV1ResponseAllOf } from './ezsignbulksendsignermapping-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './ezsignbulksendsignermapping-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksendsignermappingCreateObjectV1Response
 * Response for POST /1/object/ezsignbulksendsignermapping
 * @export
 */
export type EzsignbulksendsignermappingCreateObjectV1Response = CommonResponse & EzsignbulksendsignermappingCreateObjectV1ResponseAllOf;


/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendsignermappingCreateObjectV1Response
 */
export class DefaultObjectEzsignbulksendsignermappingCreateObjectV1Response extends DefaultObject {
   mPayload:Partial<EzsignbulksendsignermappingCreateObjectV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


