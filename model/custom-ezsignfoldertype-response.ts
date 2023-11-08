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
 * A Custom Ezsignfoldertype Object
 * @export
 * @interface CustomEzsignfoldertypeResponse
 */
export interface CustomEzsignfoldertypeResponse {
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof CustomEzsignfoldertypeResponse
     */
    'pkiEzsignfoldertypeID': number;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof CustomEzsignfoldertypeResponse
     */
    'sEzsignfoldertypeNameX'?: string;
    /**
     * Whether we include the proof with the signed Ezsigndocument for Ezsignsigners
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    'bEzsignfoldertypeIncludeproofsigner'?: boolean;
    /**
     * Whether we include the proof with the signed Ezsigndocument for users
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    'bEzsignfoldertypeIncludeproofuser'?: boolean;
    /**
     * Wheter if delegation of signature is allowed to another user or not
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    'bEzsignfoldertypeDelegate'?: boolean;
    /**
     * Wheter if Reassignment of signature is allowed to another signatory or not
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    'bEzsignfoldertypeReassign'?: boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignfoldertypeResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignfoldertypeResponse
 */
export class DataObjectCustomEzsignfoldertypeResponse {
   pkiEzsignfoldertypeID:number = 0
   sEzsignfoldertypeNameX?:string = undefined
   bEzsignfoldertypeIncludeproofsigner?:boolean = undefined
   bEzsignfoldertypeIncludeproofuser?:boolean = undefined
   bEzsignfoldertypeDelegate?:boolean = undefined
   bEzsignfoldertypeReassign?:boolean = undefined
}

/**
 * @export 
 * A CustomEzsignfoldertypeResponse Validation Object
 * @class ValidationObjectCustomEzsignfoldertypeResponse
 */
export class ValidationObjectCustomEzsignfoldertypeResponse {
   pkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: false
   }
   bEzsignfoldertypeIncludeproofsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeIncludeproofuser = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeDelegate = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeReassign = {
      type: 'boolean',
      required: false
   }
} 

