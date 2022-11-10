/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationCreateObjectV1ResponseMPayload } from './ezsignfoldersignerassociation-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignfoldersignerassociationCreateObjectV1ResponseAllOf
 */
export interface EzsignfoldersignerassociationCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfoldersignerassociationCreateObjectV1ResponseMPayload}
     * @memberof EzsignfoldersignerassociationCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsignfoldersignerassociationCreateObjectV1ResponseMPayload;
}
/**
 * A EzsignfoldersignerassociationCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldersignerassociationCreateObjectV1ResponseAllOf
 */
export class DefaultObjectEzsignfoldersignerassociationCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignfoldersignerassociationCreateObjectV1ResponseMPayload> = {}
}


