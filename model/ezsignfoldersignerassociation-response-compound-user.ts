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



/**
 * A Ezsignfoldersignerassociation->User Object and children to create a complete structure
 * @export
 * @interface EzsignfoldersignerassociationResponseCompoundUser
 */
export interface EzsignfoldersignerassociationResponseCompoundUser {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'pkiUserID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'fkiLanguageID': number;
    /**
     * The first name of the user
     * @type {string}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'sUserFirstname': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'sUserLastname': string;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'sEmailAddress': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldersignerassociationResponseCompoundUser Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationResponseCompoundUser
 */
export class DataObjectEzsignfoldersignerassociationResponseCompoundUser {
   pkiUserID:number = 0
   fkiLanguageID:number = 0
   sUserFirstname:string = ''
   sUserLastname:string = ''
   sEmailAddress:string = ''
}

/**
 * @export 
 * A EzsignfoldersignerassociationResponseCompoundUser Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationResponseCompoundUser
 */
export class ValidationObjectEzsignfoldersignerassociationResponseCompoundUser {
   pkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sUserFirstname = {
      type: 'string',
      required: true
   }
   sUserLastname = {
      type: 'string',
      required: true
   }
   sEmailAddress = {
      type: 'string',
      required: true
   }
} 


