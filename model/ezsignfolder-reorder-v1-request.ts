/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/reorder
 * @export
 * @interface EzsignfolderReorderV1Request
 */
export interface EzsignfolderReorderV1Request {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfolderReorderV1Request
     */
    /*'a_pkiEzsigndocumentID': Array<number>;*/
    'a_pkiEzsigndocumentID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderReorderV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderReorderV1Request
 */
export class DataObjectEzsignfolderReorderV1Request {
   a_pkiEzsigndocumentID:Array<number> = []
}

/**
 * @export 
 * A EzsignfolderReorderV1Request Validation Object
 * @class ValidationObjectEzsignfolderReorderV1Request
 */
export class ValidationObjectEzsignfolderReorderV1Request {
   a_pkiEzsigndocumentID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


