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


// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfoldersignerassociationResponseCompound } from './ezsignfoldersignerassociation-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfoldersignerassociationResponseCompoundUser } from './ezsignfoldersignerassociation-response-compound-user';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignerResponseCompound } from './ezsignsigner-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignergroupResponseCompound } from './ezsignsignergroup-response-compound';

/**
 * @type CustomEzsignfoldersignerassociationActionableElementResponse
 * A Ezsignfoldersignerassociation Object with actionable elements
 * @export
 */
/*export type CustomEzsignfoldersignerassociationActionableElementResponse = EzsignfoldersignerassociationResponseCompound;*/
export interface CustomEzsignfoldersignerassociationActionableElementResponse {
    /**
     * Indicates if the Ezsignfoldersignerassociation has actionable elements in the current step
     * @type {boolean}
     * @memberof CustomEzsignfoldersignerassociationActionableElementResponse
     */
    bEzsignfoldersignerassociationHasactionableelementsCurrent:boolean 
    /**
     * Indicates if the Ezsignfoldersignerassociation has actionable elements in a future step
     * @type {boolean}
     * @memberof CustomEzsignfoldersignerassociationActionableElementResponse
     */
    bEzsignfoldersignerassociationHasactionableelementsFuture:boolean 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignfoldersignerassociationActionableElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignfoldersignerassociationActionableElementResponse
 */
export class DataObjectCustomEzsignfoldersignerassociationActionableElementResponse {
    bEzsignfoldersignerassociationHasactionableelementsCurrent:boolean = false
    bEzsignfoldersignerassociationHasactionableelementsFuture:boolean = false
}

/**
 * @export 
 * A CustomEzsignfoldersignerassociationActionableElementResponse Validation Object
 * @class ValidationObjectCustomEzsignfoldersignerassociationActionableElementResponse
 */
export class ValidationObjectCustomEzsignfoldersignerassociationActionableElementResponse {
   bEzsignfoldersignerassociationHasactionableelementsCurrent = {
      type: 'boolean',
      required: true
   }
   bEzsignfoldersignerassociationHasactionableelementsFuture = {
      type: 'boolean',
      required: true
   }
} 


