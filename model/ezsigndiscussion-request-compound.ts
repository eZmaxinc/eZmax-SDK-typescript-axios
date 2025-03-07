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


// May contain unused imports in some cases
// @ts-ignore
import type { DiscussionRequest } from './discussion-request';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigndiscussionRequest } from './ezsigndiscussion-request';

/**
 * @type EzsigndiscussionRequestCompound
 * A Ezsigndiscussion Object and children
 * @export
 */
/*export type EzsigndiscussionRequestCompound = EzsigndiscussionRequest;*/
export interface EzsigndiscussionRequestCompound {
    /**
     * The unique ID of the Ezsigndiscussion
     * @type {number}
     * @memberof EzsigndiscussionRequestCompound
     */
    pkiEzsigndiscussionID?:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsigndiscussionRequestCompound
     */
    fkiEzsigndocumentID:number 
    /**
     * The page number in the Ezsigndocument for the Ezsigndiscussion
     * @type {number}
     * @memberof EzsigndiscussionRequestCompound
     */
    iEzsigndiscussionPagenumber:number 
    /**
     * The x of the Ezsigndiscussion
     * @type {number}
     * @memberof EzsigndiscussionRequestCompound
     */
    iEzsigndiscussionX:number 
    /**
     * The y of the Ezsigndiscussion
     * @type {number}
     * @memberof EzsigndiscussionRequestCompound
     */
    iEzsigndiscussionY:number 
    /**
     * 
     * @type {DiscussionRequest}
     * @memberof EzsigndiscussionRequestCompound
     */
    objDiscussion:DiscussionRequest 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectDiscussionRequest } from './'
// @ts-ignore
import { ValidationObjectDiscussionRequest } from './'

/**
 * @export 
 * A EzsigndiscussionRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndiscussionRequestCompound
 */
export class DataObjectEzsigndiscussionRequestCompound {
    pkiEzsigndiscussionID?:number = undefined
    fkiEzsigndocumentID:number = 0
    iEzsigndiscussionPagenumber:number = 0
    iEzsigndiscussionX:number = 0
    iEzsigndiscussionY:number = 0
    objDiscussion:DiscussionRequest = new DataObjectDiscussionRequest()
}

/**
 * @export 
 * A EzsigndiscussionRequestCompound Validation Object
 * @class ValidationObjectEzsigndiscussionRequestCompound
 */
export class ValidationObjectEzsigndiscussionRequestCompound {
   pkiEzsigndiscussionID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigndiscussionPagenumber = {
      type: 'integer',
      required: true
   }
   iEzsigndiscussionX = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   iEzsigndiscussionY = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   objDiscussion = new ValidationObjectDiscussionRequest()
} 


