/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupResponseCompound } from './ezsigntemplateformfieldgroup-response-compound';

/**
 * Payload for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocument}/getEzsigntemplateformfieldgroups
 * @export
 * @interface EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload
 */
export interface EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigntemplateformfieldgroupResponseCompound>}
     * @memberof EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload
     */
    'a_objEzsigntemplateformfieldgroup': Array<EzsigntemplateformfieldgroupResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload
 */
export class DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload {
   a_objEzsigntemplateformfieldgroup:Array<EzsigntemplateformfieldgroupResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload {
   a_objEzsigntemplateformfieldgroup = {
      type: 'array',
      required: true
   }
} 


