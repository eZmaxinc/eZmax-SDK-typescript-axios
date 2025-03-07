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
 * Payload for GET /1/object/ezsignfoldersignerassociation/getInPersonLoginUrl
 * @export
 * @interface EzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload
 */
export interface EzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload {
    /**
     * The Url to login to the signing application.    Url will expire after 30 minutes.  
     * @type {string}
     * @memberof EzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload
     */
    /*'sLoginUrl': string;*/
    'sLoginUrl': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload
 */
export class DataObjectEzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload {
   sLoginUrl:string = ''
}

/**
 * @export 
 * A EzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload
 */
export class ValidationObjectEzsignfoldersignerassociationGetInPersonLoginUrlV1ResponseMPayload {
   sLoginUrl = {
      type: 'string',
      required: true
   }
} 


