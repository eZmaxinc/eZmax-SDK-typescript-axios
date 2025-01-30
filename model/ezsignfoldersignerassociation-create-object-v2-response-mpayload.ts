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
 * Payload for POST /2/object/ezsignfoldersignerassociation
 * @export
 * @interface EzsignfoldersignerassociationCreateObjectV2ResponseMPayload
 */
export interface EzsignfoldersignerassociationCreateObjectV2ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsignfoldersignerassociationCreateObjectV2ResponseMPayload
     */
    /*'a_pkiEzsignfoldersignerassociationID': Array<number>;*/
    'a_pkiEzsignfoldersignerassociationID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationCreateObjectV2ResponseMPayload
 */
export class DataObjectEzsignfoldersignerassociationCreateObjectV2ResponseMPayload {
   a_pkiEzsignfoldersignerassociationID:Array<number> = []
}

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationCreateObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignfoldersignerassociationCreateObjectV2ResponseMPayload {
   a_pkiEzsignfoldersignerassociationID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


