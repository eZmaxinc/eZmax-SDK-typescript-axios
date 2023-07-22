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


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderResponse } from './ezsignfolder-response';

/**
 * 
 * @export
 * @interface WebhookEzsignFolderCompletedAllOf
 */
export interface WebhookEzsignFolderCompletedAllOf {
    /**
     * 
     * @type {EzsignfolderResponse}
     * @memberof WebhookEzsignFolderCompletedAllOf
     */
    'objEzsignfolder': EzsignfolderResponse;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderResponse } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderResponse } from './'

/**
 * @export 
 * A WebhookEzsignFolderCompletedAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookEzsignFolderCompletedAllOf
 */
export class DataObjectWebhookEzsignFolderCompletedAllOf {
   objEzsignfolder:EzsignfolderResponse = new DataObjectEzsignfolderResponse()
}

/**
 * @export 
 * A WebhookEzsignFolderCompletedAllOf Validation Object
 * @class ValidationObjectWebhookEzsignFolderCompletedAllOf
 */
export class ValidationObjectWebhookEzsignFolderCompletedAllOf {
   objEzsignfolder = new ValidationObjectEzsignfolderResponse()
} 


