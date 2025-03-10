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
import type { DiscussionResponseCompound } from './discussion-response-compound';

/**
 * A Ezsigndiscussion Object
 * @export
 * @interface EzsigndiscussionResponse
 */
export interface EzsigndiscussionResponse {
    /**
     * The unique ID of the Ezsigndiscussion
     * @type {number}
     * @memberof EzsigndiscussionResponse
     */
    /*'pkiEzsigndiscussionID': number;*/
    'pkiEzsigndiscussionID': number;
    /**
     * The unique ID of the Ezsignpage
     * @type {number}
     * @memberof EzsigndiscussionResponse
     */
    /*'fkiEzsignpageID': number;*/
    'fkiEzsignpageID': number;
    /**
     * The unique ID of the Discussion
     * @type {number}
     * @memberof EzsigndiscussionResponse
     */
    /*'fkiDiscussionID': number;*/
    'fkiDiscussionID': number;
    /**
     * The x of the Ezsigndiscussion
     * @type {number}
     * @memberof EzsigndiscussionResponse
     */
    /*'iEzsigndiscussionX': number;*/
    'iEzsigndiscussionX': number;
    /**
     * The y of the Ezsigndiscussion
     * @type {number}
     * @memberof EzsigndiscussionResponse
     */
    /*'iEzsigndiscussionY': number;*/
    'iEzsigndiscussionY': number;
    /**
     * The page number in the Ezsigndocument for the Ezsigndiscussion
     * @type {number}
     * @memberof EzsigndiscussionResponse
     */
    /*'iEzsigndiscussionPagenumber': number;*/
    'iEzsigndiscussionPagenumber': number;
    /**
     * 
     * @type {DiscussionResponseCompound}
     * @memberof EzsigndiscussionResponse
     */
    /*'objDiscussion': DiscussionResponseCompound;*/
    'objDiscussion': DiscussionResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectDiscussionResponseCompound } from './'
// @ts-ignore
import { ValidationObjectDiscussionResponseCompound } from './'

/**
 * @export 
 * A EzsigndiscussionResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndiscussionResponse
 */
export class DataObjectEzsigndiscussionResponse {
   pkiEzsigndiscussionID:number = 0
   fkiEzsignpageID:number = 0
   fkiDiscussionID:number = 0
   iEzsigndiscussionX:number = 0
   iEzsigndiscussionY:number = 0
   iEzsigndiscussionPagenumber:number = 0
   objDiscussion:DiscussionResponseCompound = new DataObjectDiscussionResponseCompound()
}

/**
 * @export 
 * A EzsigndiscussionResponse Validation Object
 * @class ValidationObjectEzsigndiscussionResponse
 */
export class ValidationObjectEzsigndiscussionResponse {
   pkiEzsigndiscussionID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiEzsignpageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiDiscussionID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
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
   iEzsigndiscussionPagenumber = {
      type: 'integer',
      required: true
   }
   objDiscussion = new ValidationObjectDiscussionResponseCompound()
} 


