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
    /*'pkiEzsignfoldertypeID': number;*/
    'pkiEzsignfoldertypeID': number;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof CustomEzsignfoldertypeResponse
     */
    /*'sEzsignfoldertypeNameX'?: string;*/
    'sEzsignfoldertypeNameX'?: string;
    /**
     * Whether we send the proof in the email to Ezsignsigner
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    /*'bEzsignfoldertypeSendproofezsignsigner'?: boolean;*/
    'bEzsignfoldertypeSendproofezsignsigner'?: boolean;
    /**
     * Whether we allow the Ezsigndocument to be downloaded by an Ezsignsigner
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    /*'bEzsignfoldertypeAllowdownloadattachmentezsignsigner'?: boolean;*/
    'bEzsignfoldertypeAllowdownloadattachmentezsignsigner'?: boolean;
    /**
     * Whether we allow the proof to be downloaded by an Ezsignsigner
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    /*'bEzsignfoldertypeAllowdownloadproofezsignsigner'?: boolean;*/
    'bEzsignfoldertypeAllowdownloadproofezsignsigner'?: boolean;
    /**
     * Wheter if delegation of signature is allowed to another user or not
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    /*'bEzsignfoldertypeDelegate'?: boolean;*/
    'bEzsignfoldertypeDelegate'?: boolean;
    /**
     * Wheter if creating a new Discussion is allowed or not
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    /*'bEzsignfoldertypeDiscussion'?: boolean;*/
    'bEzsignfoldertypeDiscussion'?: boolean;
    /**
     * Wheter if Reassignment of signature is allowed by a signatory to another signatory or not
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    /*'bEzsignfoldertypeReassignezsignsigner'?: boolean;*/
    'bEzsignfoldertypeReassignezsignsigner'?: boolean;
    /**
     * Wheter if Reassignment of signature is allowed by a user to a signatory or another user or not
     * @type {boolean}
     * @memberof CustomEzsignfoldertypeResponse
     */
    /*'bEzsignfoldertypeReassignuser'?: boolean;*/
    'bEzsignfoldertypeReassignuser'?: boolean;
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
   bEzsignfoldertypeSendproofezsignsigner?:boolean = undefined
   bEzsignfoldertypeAllowdownloadattachmentezsignsigner?:boolean = undefined
   bEzsignfoldertypeAllowdownloadproofezsignsigner?:boolean = undefined
   bEzsignfoldertypeDelegate?:boolean = undefined
   bEzsignfoldertypeDiscussion?:boolean = undefined
   bEzsignfoldertypeReassignezsignsigner?:boolean = undefined
   bEzsignfoldertypeReassignuser?:boolean = undefined
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
      maximum: 65535,
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: false
   }
   bEzsignfoldertypeSendproofezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeAllowdownloadattachmentezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeAllowdownloadproofezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeDelegate = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeDiscussion = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeReassignezsignsigner = {
      type: 'boolean',
      required: false
   }
   bEzsignfoldertypeReassignuser = {
      type: 'boolean',
      required: false
   }
} 


