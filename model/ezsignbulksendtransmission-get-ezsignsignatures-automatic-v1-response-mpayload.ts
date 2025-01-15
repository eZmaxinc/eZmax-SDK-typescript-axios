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
import type { CustomEzsignfolderEzsignsignaturesAutomaticResponse } from './custom-ezsignfolder-ezsignsignatures-automatic-response';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignsignatureType } from './field-eezsignsignature-type';

/**
 * Payload for GET /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getEzsignsignaturesAutomatic
 * @export
 * @interface EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload
 */
export interface EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload {
    /**
     * All eEzsignsignatureType contained in the response
     * @type {Set<FieldEEzsignsignatureType>}
     * @memberof EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload
     */
    /*'a_eEzsignsignatureType': Set<FieldEEzsignsignatureType>;*/
    'a_eEzsignsignatureType': Array<FieldEEzsignsignatureType>;
    /**
     * 
     * @type {Array<CustomEzsignfolderEzsignsignaturesAutomaticResponse>}
     * @memberof EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload
     */
    /*'a_objEzsignfolder': Array<CustomEzsignfolderEzsignsignaturesAutomaticResponse>;*/
    'a_objEzsignfolder': Array<CustomEzsignfolderEzsignsignaturesAutomaticResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload
 */
export class DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload {
   a_eEzsignsignatureType:Array<FieldEEzsignsignatureType> = []
   a_objEzsignfolder:Array<CustomEzsignfolderEzsignsignaturesAutomaticResponse> = []
}

/**
 * @export 
 * A EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload
 */
export class ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload {
   a_eEzsignsignatureType = {
      type: 'array',
      unique: true,
      required: true
   }
   a_objEzsignfolder = {
      type: 'array',
      required: true
   }
} 


