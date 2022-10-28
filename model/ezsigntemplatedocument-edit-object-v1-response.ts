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
import { CommonResponseWarning } from './common-response-warning';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentEditObjectV1ResponseAllOf } from './ezsigntemplatedocument-edit-object-v1-response-all-of';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatedocumentEditObjectV1Response
 * Response for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}
 * @export
 */
export type EzsigntemplatedocumentEditObjectV1Response = CommonResponse & EzsigntemplatedocumentEditObjectV1ResponseAllOf;


/**
 * @export 
 * A EzsigntemplatedocumentEditObjectV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatedocumentEditObjectV1Response
 */
export class DefaultObjectEzsigntemplatedocumentEditObjectV1Response extends DefaultObject {
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
   a_objWarning?:Array<CommonResponseWarning> = undefined
}


