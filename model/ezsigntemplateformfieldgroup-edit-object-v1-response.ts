/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplateformfieldgroupEditObjectV1Response
 * Response for PUT /1/object/ezsigntemplateformfieldgroup/{pkiEzsigntemplateformfieldgroupID}
 * @export
 */
export type EzsigntemplateformfieldgroupEditObjectV1Response = CommonResponse;


/**
 * @export 
 * A EzsigntemplateformfieldgroupEditObjectV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplateformfieldgroupEditObjectV1Response
 */
export class DefaultObjectEzsigntemplateformfieldgroupEditObjectV1Response extends DefaultObject {
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


