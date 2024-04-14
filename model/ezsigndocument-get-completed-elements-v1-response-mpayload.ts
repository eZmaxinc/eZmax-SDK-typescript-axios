/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupResponseCompound } from './ezsignformfieldgroup-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureResponseCompound } from './ezsignsignature-response-compound';

/**
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getCompletedElements
 * @export
 * @interface EzsigndocumentGetCompletedElementsV1ResponseMPayload
 */
export interface EzsigndocumentGetCompletedElementsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignsignatureResponseCompound>}
     * @memberof EzsigndocumentGetCompletedElementsV1ResponseMPayload
     */
    /*'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;*/
    'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;
    /**
     * 
     * @type {Array<EzsignformfieldgroupResponseCompound>}
     * @memberof EzsigndocumentGetCompletedElementsV1ResponseMPayload
     */
    /*'a_objEzsignformfieldgroup': Array<EzsignformfieldgroupResponseCompound>;*/
    'a_objEzsignformfieldgroup': Array<EzsignformfieldgroupResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentGetCompletedElementsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetCompletedElementsV1ResponseMPayload
 */
export class DataObjectEzsigndocumentGetCompletedElementsV1ResponseMPayload {
   a_objEzsignsignature:Array<EzsignsignatureResponseCompound> = []
   a_objEzsignformfieldgroup:Array<EzsignformfieldgroupResponseCompound> = []
}

/**
 * @export 
 * A EzsigndocumentGetCompletedElementsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentGetCompletedElementsV1ResponseMPayload
 */
export class ValidationObjectEzsigndocumentGetCompletedElementsV1ResponseMPayload {
   a_objEzsignsignature = {
      type: 'array',
      required: true
   }
   a_objEzsignformfieldgroup = {
      type: 'array',
      required: true
   }
} 


