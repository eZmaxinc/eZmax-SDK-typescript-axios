/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Payload for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/createEzsignelementsPositionedByWord
 * @export
 * @interface EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload
 */
export interface EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload
     */
    'a_pkiEzsignsignatureID': Array<number>;
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload
     */
    'a_pkiEzsignformfieldgroupID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload
 */
export class DataObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload {
   a_pkiEzsignsignatureID:Array<number> = []
   a_pkiEzsignformfieldgroupID:Array<number> = []
}

/**
 * @export 
 * A EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload
 */
export class ValidationObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload {
   a_pkiEzsignsignatureID = {
      type: 'array',
      required: true
   }
   a_pkiEzsignformfieldgroupID = {
      type: 'array',
      required: true
   }
} 


