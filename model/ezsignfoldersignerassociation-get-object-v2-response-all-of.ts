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
import { EzsignfoldersignerassociationGetObjectV2ResponseMPayload } from './ezsignfoldersignerassociation-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfoldersignerassociationGetObjectV2ResponseAllOf
 */
export interface EzsignfoldersignerassociationGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsignfoldersignerassociationGetObjectV2ResponseMPayload}
     * @memberof EzsignfoldersignerassociationGetObjectV2ResponseAllOf
     */
    'mPayload': EzsignfoldersignerassociationGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationGetObjectV2ResponseAllOf
 */
export class DataObjectEzsignfoldersignerassociationGetObjectV2ResponseAllOf {
   mPayload:EzsignfoldersignerassociationGetObjectV2ResponseMPayload = new DataObjectEzsignfoldersignerassociationGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignfoldersignerassociationGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationGetObjectV2ResponseAllOf
 */
export class ValidationObjectEzsignfoldersignerassociationGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectEzsignfoldersignerassociationGetObjectV2ResponseMPayload()
} 


