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



/**
 * Request for POST /1/object/ezsignfolder/disposeEzsignfolders
 * @export
 * @interface EzsignfolderDisposeEzsignfoldersV1Request
 */
export interface EzsignfolderDisposeEzsignfoldersV1Request {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfolderDisposeEzsignfoldersV1Request
     */
    /*'a_pkiEzsignfolderID': Array<number>;*/
    'a_pkiEzsignfolderID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderDisposeEzsignfoldersV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderDisposeEzsignfoldersV1Request
 */
export class DataObjectEzsignfolderDisposeEzsignfoldersV1Request {
   a_pkiEzsignfolderID:Array<number> = []
}

/**
 * @export 
 * A EzsignfolderDisposeEzsignfoldersV1Request Validation Object
 * @class ValidationObjectEzsignfolderDisposeEzsignfoldersV1Request
 */
export class ValidationObjectEzsignfolderDisposeEzsignfoldersV1Request {
   a_pkiEzsignfolderID = {
      type: 'array',
      minItems: 1,
      maxItems: 500,
      required: true
   }
} 


